// Package mapping holds the pseudonym-to-original tables that the forward
// pass builds and the return pass consumes. One Table belongs to one request
// and is stored under the host's RequestID; the same RequestID arrives with
// the request interceptor, the stream header call, every chunk and the
// completion event, so it is the only key needed.
//
// Tables hold clear-text values for as long as the request lives. They are
// removed on the request.complete lifecycle event; the TTL is the safety net
// for events that never arrive.
package mapping

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sirupsen/logrus"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// ErrNotImplemented marks a contract stub that has no implementation yet.
var ErrNotImplemented = errors.New("mapping: not implemented")

// ErrTableNotFound is returned by Store.Get for an unknown or expired
// RequestID. The return pass then passes the response through unchanged and
// logs the incident.
var ErrTableNotFound = errors.New("mapping: no table for request")

// Generator is the part of pseudo.Generator the table needs. It is an
// interface here so the table can be tested with a fake.
type Generator interface {
	Pseudonym(kind detect.Kind, value string, attempt int) string
}

// Entry is one row of a Table.
type Entry struct {
	Kind      detect.Kind
	Original  string
	Pseudonym string
	// Attempt is the collision counter that produced Pseudonym; 0 in the
	// common case.
	Attempt int
}

// maxGeneratorAttempts bounds the collision loop. A generator that ignores
// its attempt argument would otherwise spin forever under the table lock;
// past the bound the table disambiguates on its own, deterministically. With
// the real generator the bound is never reached.
const maxGeneratorAttempts = 1024

// tableKey is the identity of an entry: kind and original value together.
type tableKey struct {
	kind  detect.Kind
	value string
}

// Table maps originals to pseudonyms and back for one request. It is built
// on the forward pass and read on the return pass; a Table is safe for
// concurrent use because stream chunks may be intercepted while the table is
// still referenced by the request path.
type Table struct {
	gen Generator

	mu          sync.RWMutex
	byKey       map[tableKey]Entry
	byPseudonym map[string]Entry
	maxLen      int

	// restorer is built on the first call of Restorer and shared by every
	// response and stream chunk of the request. restorerBuilt says whether
	// that call happened, so RestoredHits does not build a trie for a
	// request that never had a response.
	restorerOnce  sync.Once
	restorer      Restorer
	restorerBuilt atomic.Bool
}

// RestoredHits returns how often each pseudonym of the table was swapped
// back by the request's restorer so far, keyed by pseudonym, or nil when no
// restorer was ever built. The map is a copy. The audit log reads it at
// request completion.
func (t *Table) RestoredHits() map[string]int {
	if !t.restorerBuilt.Load() {
		return nil
	}
	return t.Restorer().Hits()
}

// NewTable creates an empty table bound to a generator.
func NewTable(gen Generator) *Table {
	return &Table{
		gen:         gen,
		byKey:       make(map[tableKey]Entry),
		byPseudonym: make(map[string]Entry),
	}
}

// Lookup returns the pseudonym for value under kind, creating the entry on
// first use. The pair (kind, value) is the identity of an entry: the same
// pair always returns the same pseudonym within a table, and because the
// generator is deterministic, the same pseudonym across all tables of one
// conversation as long as no collision occurred.
//
// Collisions are resolved on insert: if the pseudonym for attempt 0 is
// already taken by a different (kind, value), attempt is raised until a free
// pseudonym is found. The chosen attempt is recorded in the Entry. A
// collision raises the attempt only for the later of the two values, so the
// first value keeps the pseudonym other tables of the conversation know.
func (t *Table) Lookup(kind detect.Kind, value string) string {
	key := tableKey{kind: kind, value: value}

	t.mu.RLock()
	e, ok := t.byKey[key]
	t.mu.RUnlock()
	if ok {
		return e.Pseudonym
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// Another goroutine may have inserted the entry between the two locks.
	if e, ok := t.byKey[key]; ok {
		return e.Pseudonym
	}

	attempt := 0
	var pseudonym string
	for {
		pseudonym = t.render(kind, value, attempt)
		if _, taken := t.byPseudonym[pseudonym]; !taken {
			break
		}
		attempt++
	}

	e = Entry{Kind: kind, Original: value, Pseudonym: pseudonym, Attempt: attempt}
	t.byKey[key] = e
	t.byPseudonym[pseudonym] = e
	if len(pseudonym) > t.maxLen {
		t.maxLen = len(pseudonym)
	}
	return pseudonym
}

// render asks the generator for the pseudonym of one attempt. Beyond
// maxGeneratorAttempts it appends the attempt itself, so the collision loop
// terminates even against a generator that ignores the argument.
func (t *Table) render(kind detect.Kind, value string, attempt int) string {
	if attempt < maxGeneratorAttempts {
		return t.gen.Pseudonym(kind, value, attempt)
	}
	return t.gen.Pseudonym(kind, value, maxGeneratorAttempts-1) + "#" + strconv.Itoa(attempt)
}

// Original returns the original for a pseudonym and whether it exists.
func (t *Table) Original(pseudonym string) (Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byPseudonym[pseudonym]
	return e, ok
}

// Entries returns all rows sorted by Pseudonym, for tests and diagnostics.
// The slice is a copy.
func (t *Table) Entries() []Entry {
	t.mu.RLock()
	out := make([]Entry, 0, len(t.byPseudonym))
	for _, e := range t.byPseudonym {
		out = append(out, e)
	}
	t.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Pseudonym < out[j].Pseudonym })
	return out
}

// Len returns the number of rows.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byKey)
}

// Pseudonyms returns every pseudonym in the table, sorted by descending
// length and then lexically. The return pass replaces in this order so a
// pseudonym that is a prefix of another (not possible with the default
// renderers, but not ruled out by the interface) is never matched too early.
func (t *Table) Pseudonyms() []string {
	t.mu.RLock()
	out := make([]string, 0, len(t.byPseudonym))
	for p := range t.byPseudonym {
		out = append(out, p)
	}
	t.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// MaxPseudonymLen returns the length in bytes of the longest pseudonym in
// the table, 0 for an empty table. The stream holdback is bounded by it.
func (t *Table) MaxPseudonymLen() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.maxLen
}

// Restorer returns the restorer over the table, built on the first call and
// cached: the trie is the same for every response and every stream chunk of
// a request, and building it per chunk would cost more than the restoring.
// The first call freezes the rows; the forward pass finishes the table
// before it is stored, so nothing is added afterwards.
func (t *Table) Restorer() Restorer {
	t.restorerOnce.Do(func() {
		t.restorer = NewRestorer(t)
		t.restorerBuilt.Store(true)
	})
	return t.restorer
}

// Restorer replaces pseudonyms in a text with their originals. It is built
// once per request from the table and shared by all chunks of the stream.
type Restorer interface {
	// Restore returns text with every pseudonym of the table replaced by its
	// original. escaped selects the JSON-escaped form of the originals, for
	// use inside partial_json fragments where the text is still in JSON
	// string encoding; pseudonyms are ASCII without escapable characters and
	// read the same in both forms. When nothing matches, Restore returns text
	// unchanged and changed == false.
	//
	// A pseudonym is only replaced where it stands on its own: an occurrence
	// that continues a token on either side is left untouched. Person
	// pseudonyms are ordinary words, so without that rule a pseudonym such as
	// "Ruth" would rewrite the middle of "Ruthless" in the model's answer,
	// and an address pseudonym would rewrite the front of a longer address.
	// The rule is the one of the structural detectors: letters and digits
	// continue a token, everything else delimits, the underscore included.
	// That is looser than the term list's rule, and deliberately so: a
	// pseudonym the forward pass inserted next to an underscore, as in
	// "scan_<address>.log", must come back, and restoring one the model
	// wrote there itself only shows the user a value that is their own.
	Restore(text string, escaped bool) (out string, changed bool)
	// Holdback returns the length in bytes of the tail of text that has to
	// wait for the next fragment because it may still grow into a pseudonym:
	// everything from the first position where the walk over the table's
	// pseudonyms reaches the end of text undecided. A pseudonym that is
	// complete before that position is never part of the tail, so the tail
	// never cuts into one; the case the rule exists for is a complete
	// pseudonym whose last byte happens to begin another pseudonym. The
	// stream restores what lies in front of the tail with Restore and gets
	// the same matches, because both walk the text the same way. The result
	// is 0 when nothing is pending, never splits a UTF-8 sequence and is at
	// most MaxPseudonymLen()-1.
	Holdback(text string) int
	// Hits returns how often Restore swapped each pseudonym back so far,
	// keyed by pseudonym. The map is a copy; the counting is safe for the
	// concurrent use the stream makes of one restorer.
	Hits() map[string]int
}

// trieNode is one byte of a pseudonym in the restorer's search trie. The
// trie gives a single left-to-right pass over the text: at every position at
// most one walk down the trie happens, and the walk is bounded by the longest
// pseudonym, so Restore is linear in the length of the text for the table
// sizes this plugin sees.
type trieNode struct {
	children map[byte]*trieNode
	// terminal is set on the last byte of a pseudonym.
	terminal bool
	// plain and escaped are the original in both forms, valid when terminal;
	// pseudonym is the key of the row, for the hit count.
	plain     string
	escaped   string
	pseudonym string
}

type restorer struct {
	root *trieNode
	// starts marks every byte that begins some pseudonym, so the scan skips
	// over uninteresting stretches without touching the trie.
	starts [256]bool
	maxLen int
	// hits counts the swaps per pseudonym, under hitsMu because stream
	// chunks of one request may be restored from several goroutines.
	hitsMu sync.Mutex
	hits   map[string]int
}

// Hits implements Restorer.
func (r *restorer) Hits() map[string]int {
	r.hitsMu.Lock()
	defer r.hitsMu.Unlock()
	out := make(map[string]int, len(r.hits))
	for k, v := range r.hits {
		out[k] = v
	}
	return out
}

func (r *restorer) countHit(pseudonym string) {
	r.hitsMu.Lock()
	if r.hits == nil {
		r.hits = make(map[string]int)
	}
	r.hits[pseudonym]++
	r.hitsMu.Unlock()
}

// NewRestorer builds a Restorer over the current rows of t. Rows added to t
// after this call are not seen; the request path finishes the table before
// the return pass starts, so that is not a restriction in practice. Callers
// on the request path use Table.Restorer, which builds once and caches.
func NewRestorer(t *Table) Restorer {
	r := &restorer{root: &trieNode{}}
	if t == nil {
		return r
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, e := range t.byPseudonym {
		if e.Pseudonym == "" {
			// An empty pseudonym would match everywhere and replace nothing.
			continue
		}
		r.insert(e)
		if len(e.Pseudonym) > r.maxLen {
			r.maxLen = len(e.Pseudonym)
		}
	}
	return r
}

func (r *restorer) insert(e Entry) {
	r.insertSpelling(e, e.Pseudonym, false)
	if upper := strings.ToUpper(e.Pseudonym); upper != e.Pseudonym && upperCaseRestores(e.Kind) {
		// A model writes a token in upper case in a heading or a constant
		// ("H-E2BA…", "02:E8:F5:…"); it means the same thing and comes
		// back as the same original. Person pseudonyms are excluded: their
		// case variants are distinct rows of the table.
		r.insertSpelling(e, upper, true)
	}
	if bare, ok := withoutReservedSuffix(e); ok {
		// A model reads the reserved ".invalid" of a domain or e-mail
		// pseudonym as the marker it is and writes the name without it:
		// "d-e2ba…" for "d-e2ba….invalid", "u-…@d-…" for the address. The
		// bare spelling means the same domain and comes back as the same
		// original; a suffix glued to it ("d-e2ba….bak") restores like any
		// other glued suffix. The full spelling is longer and wins where it
		// is present, so ".invalid" is never left behind.
		r.insertSpelling(e, bare, true)
		if upper := strings.ToUpper(bare); upper != bare {
			r.insertSpelling(e, upper, true)
		}
	}
}

// reservedSuffix is the top-level domain of domain and e-mail pseudonyms,
// see pseudo.SuffixDomain. It is spelled here rather than imported so that
// mapping keeps depending on detect only.
const reservedSuffix = ".invalid"

// withoutReservedSuffix returns the pseudonym of a domain or e-mail row
// without its ".invalid" and true, or "" and false for every other row.
func withoutReservedSuffix(e Entry) (string, bool) {
	if e.Kind != detect.KindDomain && e.Kind != detect.KindEmail {
		return "", false
	}
	bare := strings.TrimSuffix(e.Pseudonym, reservedSuffix)
	if bare == e.Pseudonym || bare == "" || strings.HasSuffix(bare, "@") {
		return "", false
	}
	return bare, true
}

// upperCaseRestores reports whether the pseudonyms of kind are restored in
// upper case as well. It covers the kinds whose pseudonyms are hex tokens
// or hex addresses; a person pseudonym carries its own case.
func upperCaseRestores(kind detect.Kind) bool {
	switch kind {
	case detect.KindHost, detect.KindDomain, detect.KindEmail, detect.KindPathSegment, detect.KindFileName,
		detect.KindSecret, detect.KindUUID, detect.KindHexID, detect.KindMAC, detect.KindIPv6, detect.KindCIDR:
		return true
	}
	return false
}

// insertSpelling adds one spelling of e.Pseudonym to the trie; the row's
// original and pseudonym are the same for every spelling. An alias (upper
// case, bare domain) never displaces a spelling that is already there: the
// pseudonyms of a table are distinct, so an occupied node belongs either to
// another row's own pseudonym, which keeps precedence, or to an equal alias
// of the same row.
func (r *restorer) insertSpelling(e Entry, spelling string, alias bool) {
	node := r.root
	for i := 0; i < len(spelling); i++ {
		b := spelling[i]
		if node.children == nil {
			node.children = make(map[byte]*trieNode, 4)
		}
		next, ok := node.children[b]
		if !ok {
			next = &trieNode{}
			node.children[b] = next
		}
		node = next
	}
	if alias && node.terminal {
		return
	}
	node.terminal = true
	node.plain = e.Original
	node.escaped = jsonEscape(e.Original)
	node.pseudonym = e.Pseudonym
	r.starts[spelling[0]] = true
}

// Restore implements Restorer. It walks the text once and replaces the
// longest pseudonym that starts at each position, so a pseudonym that is a
// prefix of another never wins over the longer one. Text inserted for an
// original is never rescanned. A hit that is not delimited on both sides is
// skipped; see the Restorer interface for why.
func (r *restorer) Restore(text string, escaped bool) (string, bool) {
	if r.maxLen == 0 || text == "" {
		return text, false
	}

	var b strings.Builder
	changed := false
	last := 0

	for i := 0; i < len(text); {
		if !r.starts[text[i]] {
			i++
			continue
		}
		hit, end := r.longestAt(text, i)
		if hit == nil || !delimited(text, i, end) {
			i++
			continue
		}
		if !changed {
			b.Grow(len(text) + len(text)/8)
			changed = true
		}
		b.WriteString(text[last:i])
		if escaped {
			b.WriteString(hit.escaped)
		} else {
			b.WriteString(hit.plain)
		}
		r.countHit(hit.pseudonym)
		i = end
		last = end
	}

	if !changed {
		return text, false
	}
	b.WriteString(text[last:])
	return b.String(), true
}

// longestAt returns the terminal node of the longest pseudonym starting at
// text[i] and the byte offset just behind it, or nil when none starts there.
func (r *restorer) longestAt(text string, i int) (*trieNode, int) {
	node := r.root
	var hit *trieNode
	end := 0
	for j := i; j < len(text); j++ {
		next, ok := node.children[text[j]]
		if !ok {
			break
		}
		node = next
		if node.terminal {
			hit, end = node, j+1
		}
	}
	return hit, end
}

// isTokenRune reports whether r continues a token for the boundary rule:
// letters and digits, as in the structural detectors. Dot, hyphen and the
// underscore count as separators, so an address or domain pseudonym is
// still found next to them; see the Restorer interface for why the
// underscore is not a word character here.
func isTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// delimited reports whether the match text[start:end] stands on its own. Only
// the sides that actually carry a token rune are checked: a pseudonym that
// begins or ends with punctuation may sit directly against a letter without
// growing a word, which keeps matches inside JSON and inside paths working.
//
// The edges of text count as delimiters. On the stream that is not the whole
// truth — the neighbouring rune may live in the previous or the next chunk —
// but Holdback keeps a pseudonym that could still grow whole until the next
// fragment, and one that is complete and cannot grow is restored at the edge.
// The residual case is a pseudonym split from its neighbouring word by
// exactly the chunk boundary; it is accepted, and it is the behaviour that was
// in place before the boundary rule anyway.
func delimited(text string, start, end int) bool {
	if start > 0 {
		if first, _ := utf8.DecodeRuneInString(text[start:end]); isTokenRune(first) {
			if prev, _ := utf8.DecodeLastRuneInString(text[:start]); isTokenRune(prev) {
				return false
			}
		}
	}
	if end < len(text) {
		if last, _ := utf8.DecodeLastRuneInString(text[start:end]); isTokenRune(last) {
			if next, _ := utf8.DecodeRuneInString(text[end:]); isTokenRune(next) {
				return false
			}
		}
	}
	return true
}

// Holdback implements Restorer. It is the scan of Restore without the
// output: at every position that begins a pseudonym the trie is walked as
// far as the text goes. A walk that ends inside the text is decided, and
// the scan goes on behind the match, or one byte further when there is
// none or it is not delimited. A walk that consumes the text to its end
// while the trie could go on is undecided, and everything from its start
// is held back, a complete shorter match inside it included: the next
// fragment may turn it into a longer pseudonym, and the scan of the joined
// text decides. A held tail is shorter than the pseudonym it could become,
// and it begins at a pseudonym's first byte, which is ASCII, so it never
// splits a rune.
//
// Before this scan the holdback was the longest suffix that is a proper
// prefix of some pseudonym, which cut a complete pseudonym in two whenever
// its last byte could begin another one: "d-…d" followed by a fragment
// boundary lost its last byte to the holdback, and neither piece was ever
// restored. Path segment pseudonyms end in a hex digit and begin with "d",
// so one in sixteen of them was at risk at every fragment boundary.
func (r *restorer) Holdback(text string) int {
	if r.maxLen == 0 {
		return 0
	}
	for i := 0; i < len(text); {
		if !r.starts[text[i]] {
			i++
			continue
		}
		if i > 0 {
			// A pseudonym that would continue the word in front of it is
			// never restored, so it is not worth waiting for either.
			prev, _ := utf8.DecodeLastRuneInString(text[:i])
			first, _ := utf8.DecodeRuneInString(text[i:])
			if isTokenRune(prev) && isTokenRune(first) {
				i++
				continue
			}
		}
		node := r.root
		var hit *trieNode
		end := 0
		j := i
		for ; j < len(text); j++ {
			next, ok := node.children[text[j]]
			if !ok {
				break
			}
			node = next
			if node.terminal {
				hit, end = node, j+1
			}
		}
		if j == len(text) && len(node.children) > 0 {
			return len(text) - i
		}
		if hit != nil && delimited(text, i, end) {
			i = end
			continue
		}
		i++
	}
	return 0
}

// jsonEscape returns s in the form encoding/json writes it into a string,
// without HTML escaping and without the surrounding quotes.
func jsonEscape(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		// json.Encoder only fails on unsupported types; a string is never one.
		return s
	}
	out := strings.TrimRight(buf.String(), "\n")
	if len(out) >= 2 && out[0] == '"' && out[len(out)-1] == '"' {
		return out[1 : len(out)-1]
	}
	return out
}

// StoreConfig bounds the store.
type StoreConfig struct {
	// TTL is how long a table lives without being removed by the completion
	// event. Default 10 minutes.
	TTL time.Duration
	// MaxTables is the number of tables kept at once. When it is reached, the
	// oldest table is evicted and the eviction is logged. Default 1024.
	MaxTables int
	// Now returns the current time; nil means time.Now. Tests inject a clock.
	Now func() time.Time
}

const (
	defaultTTL       = 10 * time.Minute
	defaultMaxTables = 1024
)

// storeEntry is one held table with the moment it was stored. seq breaks ties
// when the clock stands still between two Puts, so eviction stays in
// insertion order.
type storeEntry struct {
	table  *Table
	stored time.Time
	seq    uint64
}

// Store keeps tables by RequestID. It is safe for concurrent use.
type Store struct {
	ttl      time.Duration
	maxTable int
	now      func() time.Time

	mu     sync.Mutex
	tables map[string]storeEntry
	seq    uint64
}

// NewStore creates a store. Zero fields of cfg take their defaults.
func NewStore(cfg StoreConfig) *Store {
	s := &Store{
		ttl:      cfg.TTL,
		maxTable: cfg.MaxTables,
		now:      cfg.Now,
		tables:   make(map[string]storeEntry),
	}
	if s.ttl <= 0 {
		s.ttl = defaultTTL
	}
	if s.maxTable <= 0 {
		s.maxTable = defaultMaxTables
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Put stores t under requestID, replacing an existing table with the same
// ID. The TTL starts now.
func (s *Store) Put(requestID string, t *Table) {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked(now)
	_, replacing := s.tables[requestID]
	if !replacing {
		for len(s.tables) >= s.maxTable {
			id, ok := s.oldestLocked()
			if !ok {
				break
			}
			delete(s.tables, id)
			logrus.WithFields(logrus.Fields{
				"request_id": id,
				"max_tables": s.maxTable,
			}).Warn("privacyfilter: mapping store full, evicted oldest table; its response will not be restored")
		}
	}

	s.seq++
	s.tables[requestID] = storeEntry{table: t, stored: now, seq: s.seq}
}

// Get returns the table for requestID or ErrTableNotFound if it is unknown
// or expired. Get does not extend the TTL.
func (s *Store) Get(requestID string) (*Table, error) {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.tables[requestID]
	if !ok {
		return nil, ErrTableNotFound
	}
	if s.expiredLocked(e, now) {
		delete(s.tables, requestID)
		return nil, ErrTableNotFound
	}
	return e.table, nil
}

// Delete removes the table for requestID. Deleting an unknown ID is a no-op.
// The lifecycle handler calls it on request.complete.
func (s *Store) Delete(requestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tables, requestID)
}

// SetTTL changes the lifetime applied to every table, held ones included,
// from their own stored time. The store outlives the plugin instance that
// created it, so a configuration reload with a new mapping_ttl reaches the
// tables through this instead of through a new store. A non-positive
// value keeps the current TTL.
func (s *Store) SetTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = ttl
}

// Sweep removes expired tables and returns how many it removed. Get and Put
// also drop expired tables lazily; Sweep exists so a background ticker can
// bound memory when a request never completes.
func (s *Store) Sweep() int {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(now)
}

// Len returns the number of tables currently held, including expired ones
// that have not been swept yet.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tables)
}

func (s *Store) expiredLocked(e storeEntry, now time.Time) bool {
	return !now.Before(e.stored.Add(s.ttl))
}

func (s *Store) sweepLocked(now time.Time) int {
	n := 0
	for id, e := range s.tables {
		if s.expiredLocked(e, now) {
			delete(s.tables, id)
			n++
		}
	}
	return n
}

// oldestLocked returns the RequestID of the table stored first.
func (s *Store) oldestLocked() (string, bool) {
	var (
		oldest storeEntry
		id     string
		found  bool
	)
	for candidateID, e := range s.tables {
		if !found || e.stored.Before(oldest.stored) ||
			(e.stored.Equal(oldest.stored) && e.seq < oldest.seq) {
			oldest, id, found = e, candidateID, true
		}
	}
	return id, found
}
