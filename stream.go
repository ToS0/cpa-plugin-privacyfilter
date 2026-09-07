package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var _ pluginapi.StreamChunkInterceptor = (*privacyFilterPlugin)(nil)

// errStreamPanic marks a recovered panic while restoring a stream chunk.
var errStreamPanic = errors.New("privacyfilter: recovered panic on the stream")

// blockHold is the text held back at the end of one content block: the
// longest suffix of what has been seen that could be the beginning of a
// pseudonym. It is prepended to the next fragment of the block and flushed
// as a synthetic delta before the block's stop event.
type blockHold struct {
	tail      mapping.Tail
	deltaType string
	escaped   bool
}

// text returns the held text of the block.
func (h *blockHold) text() string { return h.tail.Held() }

// streamState is the return-path state of one streamed response. It lives
// from the header-init call to request.complete and is replaced by every
// header-init call, because the host repeats that call when it retries the
// upstream connection and then counts the chunks from zero again.
type streamState struct {
	mu       sync.Mutex
	restorer mapping.Restorer
	holds    map[int]*blockHold
	// restored counts events whose text changed, flushed the synthetic
	// deltas, for the log line at message_stop.
	restored int
	flushed  int
	// missing is set when no table exists for the request, so the miss is
	// logged once and every further chunk passes through quietly.
	missing bool
}

// streams holds the streamState of every open stream by RequestID. Like the
// mapping store it belongs to the runtimeState, not to a plugin instance;
// see runtimeState in main.go for why.
type streams struct {
	mu     sync.Mutex
	states map[string]*streamState
}

func newStreams() *streams {
	return &streams{states: make(map[string]*streamState)}
}

func (s *streams) get(requestID string) *streamState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[requestID]
}

func (s *streams) put(requestID string, st *streamState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[requestID] = st
}

// finish drops the state of a completed request and writes the log line of
// the stream: how many events were restored and how many synthetic deltas
// flushed the holdback. A holdback that is still pending here was never
// flushed, which means the upstream ended the stream without a stop event.
func (s *streams) finish(requestID string, stream bool) {
	s.mu.Lock()
	st := s.states[requestID]
	delete(s.states, requestID)
	s.mu.Unlock()
	if st == nil || !stream || st.missing {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	pending := 0
	for _, h := range st.holds {
		if h.text() != "" {
			pending++
		}
	}
	fields := log.Fields{"restored": st.restored, "flushed": st.flushed}
	if pending > 0 {
		fields["unflushed_blocks"] = pending
		log.WithFields(fields).Warn("privacyfilter: stream ended with text still held back")
		return
	}
	if st.restored == 0 {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(fields).Debug("privacyfilter: stream carried no pseudonym")
		}
		return
	}
	log.WithFields(fields).Info("privacyfilter: stream restored")
}

// prune drops the state of every stream whose table the store no longer
// holds. It runs on each header-init call, so the map is bounded by the
// number of live tables even if completions never arrive.
func (s *streams) prune(store *mapping.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.states {
		if !store.Has(id) {
			delete(s.states, id)
		}
	}
}

// InterceptStreamChunk is the return path for a streamed Messages response.
// The header-init call fetches the table and resets the state; every payload
// chunk is one or more complete SSE events. Text fragments are restored with
// a holdback: the tail that could still grow into a pseudonym waits for the
// next fragment, a complete pseudonym at the very end included, because the
// next byte may still glue it to a word. It is at most as long as the
// longest pseudonym, never splits a UTF-8 sequence and never cuts into a
// pseudonym that is already complete; see Restorer.Holdback and
// mapping.Tail, which also carries whether the byte in front of a fragment
// continued a word. The holdback of a block is flushed as a
// synthetic delta in front of content_block_stop, and whatever is left in
// front of message_stop and in front of an error event, because the host
// makes no final call.
//
// As on the non-streaming path, nothing here is fatal: a missing table, an
// event that does not parse or a panic pass the chunk through as it came.
func (p *privacyFilterPlugin) InterceptStreamChunk(ctx context.Context, req pluginapi.StreamChunkInterceptRequest) (pluginapi.StreamChunkInterceptResponse, error) {
	resp := pluginapi.StreamChunkInterceptResponse{}
	if p.store == nil || p.streams == nil || req.RequestID == "" || p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp, nil
	}
	if req.SourceFormat != payload.FormatClaude {
		if req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex {
			log.Warnf("privacyfilter: stream for format %q passed through with pseudonyms, only %q is restored", req.SourceFormat, payload.FormatClaude)
		}
		return resp, nil
	}

	if req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex {
		p.streams.prune(p.store)
		p.streams.put(req.RequestID, p.newStreamState(req.RequestID))
		return resp, nil
	}
	if len(req.Body) == 0 {
		return resp, nil
	}

	st := p.streams.get(req.RequestID)
	if st == nil {
		// No header-init call was seen: the state was pruned, or the
		// stream began on an instance that had restore.stream off. Start
		// from the table, which outlives instances.
		st = p.newStreamState(req.RequestID)
		p.streams.put(req.RequestID, st)
	}
	if st.missing {
		return resp, nil
	}

	out, drop, err := st.chunk(req.Body)
	if err != nil {
		log.Warnf("privacyfilter: stream chunk passed through: %v", err)
		return resp, nil
	}
	resp.DropChunk = drop
	if !drop {
		resp.Body = out
	}
	return resp, nil
}

// newStreamState builds the state for one stream from its table, or a
// state that passes everything through when the table is gone.
func (p *privacyFilterPlugin) newStreamState(requestID string) *streamState {
	table, err := p.store.Get(requestID)
	if err != nil {
		log.Warnf("privacyfilter: no mapping table for the stream, passing it through with pseudonyms")
		return &streamState{missing: true}
	}
	return &streamState{restorer: table.Restorer(), holds: make(map[int]*blockHold)}
}

// chunk restores the events of one chunk. It returns the new chunk body,
// or drop == true when every event of the chunk went into the holdback and
// nothing is left to deliver. out is nil when no byte changed, so the host
// keeps the chunk as it is.
//
// An event that cannot be read passes through as it came and the chunk goes
// on; the events in front of it have already moved text into the holdback,
// and handing the whole chunk back raw would deliver that text twice, once
// raw and once from the holdback. A chunk that does not parse as events at
// all has moved nothing and is handed back whole. A panic restores the
// holdback of before the chunk for the same reason.
func (st *streamState) chunk(body []byte) (out []byte, drop bool, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	saved := st.snapshot()
	defer func() {
		if r := recover(); r != nil {
			st.restore(saved)
			err = fmt.Errorf("%w: %v", errStreamPanic, r)
		}
	}()

	events, errParse := payload.ParseEvents(body)
	if errParse != nil {
		return nil, false, errParse
	}
	var buf bytes.Buffer
	changed := false
	dropped := 0
	for _, ev := range events {
		raw, keep, errEvent := st.event(ev)
		if errEvent != nil {
			log.Warnf("privacyfilter: stream event passed through: %v", errEvent)
			raw, keep = ev.Raw, true
		}
		if !keep {
			dropped++
			changed = true
			continue
		}
		if !bytes.Equal(raw, ev.Raw) {
			changed = true
		}
		buf.Write(raw)
	}
	if !changed {
		return nil, false, nil
	}
	if dropped == len(events) {
		return nil, true, nil
	}
	return buf.Bytes(), false, nil
}

// snapshot copies the holdback and the counters, so a chunk that panics can
// leave the state as it found it.
func (st *streamState) snapshot() streamSnapshot {
	holds := make(map[int]blockHold, len(st.holds))
	for i, h := range st.holds {
		holds[i] = *h
	}
	return streamSnapshot{holds: holds, restored: st.restored, flushed: st.flushed}
}

// restore puts a snapshot back.
func (st *streamState) restore(s streamSnapshot) {
	st.holds = make(map[int]*blockHold, len(s.holds))
	for i, h := range s.holds {
		hold := h
		st.holds[i] = &hold
	}
	st.restored, st.flushed = s.restored, s.flushed
}

// streamSnapshot is the state of a stream before a chunk, by value.
type streamSnapshot struct {
	holds    map[int]blockHold
	restored int
	flushed  int
}

// event returns the bytes to deliver for one event, and keep == false when
// the event vanishes into the holdback. Stop events are preceded by the
// flushed holdback of their block, and so is an error event: it ends the
// stream, the host makes no further call, and text that still waited for
// its next fragment would otherwise never reach the client.
func (st *streamState) event(ev payload.Event) (raw []byte, keep bool, err error) {
	switch ev.Type {
	case payload.EventContentBlockStop:
		return st.flushBefore(ev.Raw, ev.Index), true, nil
	case payload.EventMessageStop, payload.EventError:
		return st.flushBefore(ev.Raw, -1), true, nil
	}

	field, ok := payload.ReplaceableText(ev)
	if !ok {
		return ev.Raw, true, nil
	}
	text, errGet := payload.GetText(ev, field)
	if errGet != nil {
		return nil, false, errGet
	}

	if !payload.Streamed(ev) {
		restored, changed := st.restorer.Restore(text, field.Escaped)
		if !changed {
			return ev.Raw, true, nil
		}
		st.restored++
		out, errSet := payload.SetText(ev, field, restored)
		return out, true, errSet
	}

	hold := st.holds[ev.Index]
	if hold == nil {
		hold = &blockHold{tail: mapping.NewTail(st.restorer), escaped: field.Escaped, deltaType: payload.DeltaText}
		if field.Escaped {
			hold.deltaType = payload.DeltaInputJSON
		}
		st.holds[ev.Index] = hold
	}
	restored, changed := hold.tail.Push(text, field.Escaped)
	if restored == "" {
		// Everything waits for the next fragment. An empty delta would be
		// harmless but pointless; the event is dropped instead.
		return nil, false, nil
	}
	if changed {
		st.restored++
	}
	if !changed && restored == text {
		// Nothing was held back before, nothing is held back now, and no
		// pseudonym was in it: the event goes out as it came.
		return ev.Raw, true, nil
	}
	out, errSet := payload.SetText(ev, field, restored)
	return out, true, errSet
}

// flushBefore returns the holdback of block index, or of every block when
// index is negative, as synthetic deltas followed by raw.
func (st *streamState) flushBefore(raw []byte, index int) []byte {
	var indexes []int
	if index >= 0 {
		if _, ok := st.holds[index]; ok {
			indexes = []int{index}
		}
	} else {
		for i := range st.holds {
			indexes = append(indexes, i)
		}
		sort.Ints(indexes)
	}
	if len(indexes) == 0 {
		return raw
	}
	var buf bytes.Buffer
	for _, i := range indexes {
		hold := st.holds[i]
		delete(st.holds, i)
		restored, changed := hold.tail.Flush(hold.escaped)
		if restored == "" {
			continue
		}
		if changed {
			st.restored++
		}
		st.flushed++
		buf.Write(payload.SyntheticDelta(i, hold.deltaType, restored))
	}
	if buf.Len() == 0 {
		return raw
	}
	buf.Write(raw)
	return buf.Bytes()
}
