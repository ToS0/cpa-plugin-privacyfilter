package payload_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

const (
	evText      = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hallo h-0badcafe, alles\"}}\n\n"
	evJSON      = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\": \\\"ssh h-0bad\"}}\n\n"
	evThinking  = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"h-0badcafe pingen\"}}\n\n"
	evSignature = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"EqQBCkYI\"}}\n\n"
	evStop      = "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
	evStart     = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-fable-5-1\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"
	evBlockText = "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
	evPing      = "event: ping\ndata: {\"type\": \"ping\"}\n\n"
)

func TestParseEvent(t *testing.T) {
	ev, err := payload.ParseEvent([]byte(evText))
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.Type != payload.EventContentBlockDelta || ev.Index != 1 || ev.DeltaType != payload.DeltaText {
		t.Fatalf("ParseEvent = %+v", ev)
	}
	if !bytes.Equal(ev.Raw, []byte(evText)) || !json.Valid(ev.Data) || bytes.HasPrefix(ev.Data, []byte("data:")) {
		t.Fatalf("Raw/Data wrong: raw=%q data=%q", ev.Raw, ev.Data)
	}
	ping, err := payload.ParseEvent([]byte(evPing))
	if err != nil || ping.Type != payload.EventPing || ping.Index != -1 || ping.DeltaType != "" {
		t.Fatalf("ping = %+v, %v", ping, err)
	}
	if _, err := payload.ParseEvent([]byte("event: x\n\n")); err == nil {
		t.Fatal("event without data line must return an error")
	}
	if _, err := payload.ParseEvent([]byte("data: not json\n\n")); err == nil {
		t.Fatal("non-JSON data must return an error")
	}
}

func TestParseEvents_Multiple(t *testing.T) {
	evs, err := payload.ParseEvents([]byte(evStart + evBlockText + evText))
	if err != nil {
		t.Fatalf("ParseEvents: %v", err)
	}
	if len(evs) != 3 || evs[0].Type != payload.EventMessageStart || evs[2].DeltaType != payload.DeltaText {
		t.Fatalf("ParseEvents = %+v", evs)
	}
}

func TestReplaceableText(t *testing.T) {
	cases := []struct {
		raw     string
		ok      bool
		path    string
		escaped bool
	}{
		{evText, true, "delta.text", false},
		{evJSON, true, "delta.partial_json", true},
		{evBlockText, true, "content_block.text", false},
		{evThinking, false, "", false},
		{evSignature, false, "", false},
		{evStop, false, "", false},
		{evStart, false, "", false},
		{evPing, false, "", false},
	}
	for _, c := range cases {
		ev, err := payload.ParseEvent([]byte(c.raw))
		if err != nil {
			t.Fatalf("ParseEvent(%q): %v", c.raw, err)
		}
		f, ok := payload.ReplaceableText(ev)
		if ok != c.ok {
			t.Errorf("ReplaceableText(%s/%s) ok = %v, want %v", ev.Type, ev.DeltaType, ok, c.ok)
			continue
		}
		if ok && (f.Path.String() != c.path || f.Escaped != c.escaped) {
			t.Errorf("ReplaceableText(%s/%s) = %+v, want %s escaped=%v", ev.Type, ev.DeltaType, f, c.path, c.escaped)
		}
	}
}

func TestSetText_PreservesEverythingElse(t *testing.T) {
	ev, _ := payload.ParseEvent([]byte(evText))
	f, _ := payload.ReplaceableText(ev)
	out, err := payload.SetText(ev, f, "Hallo athene.lan, alles \"gut\" <ok>")
	if err != nil {
		t.Fatalf("SetText: %v", err)
	}
	want := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hallo athene.lan, alles \\\"gut\\\" <ok>\"}}\n\n"
	if string(out) != want {
		t.Fatalf("SetText =\n%q\nwant\n%q", out, want)
	}
	// partial_json: the caller passes text that is already JSON-escaped
	// fragment content; SetText escapes it once more as any string value.
	ev2, _ := payload.ParseEvent([]byte(evJSON))
	f2, _ := payload.ReplaceableText(ev2)
	out2, err := payload.SetText(ev2, f2, `{"command": "ssh athene.lan`)
	if err != nil {
		t.Fatalf("SetText: %v", err)
	}
	want2 := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\": \\\"ssh athene.lan\"}}\n\n"
	if string(out2) != want2 {
		t.Fatalf("SetText(partial_json) =\n%q\nwant\n%q", out2, want2)
	}
}

func TestSyntheticDelta(t *testing.T) {
	raw := payload.SyntheticDelta(3, payload.DeltaText, "rest")
	ev, err := payload.ParseEvent(raw)
	if err != nil {
		t.Fatalf("synthetic event does not parse: %v\n%q", err, raw)
	}
	if ev.Type != payload.EventContentBlockDelta || ev.Index != 3 || ev.DeltaType != payload.DeltaText {
		t.Fatalf("synthetic = %+v", ev)
	}
	f, ok := payload.ReplaceableText(ev)
	if !ok {
		t.Fatal("synthetic delta must carry replaceable text")
	}
	var data struct {
		Delta map[string]string `json:"delta"`
	}
	if err := json.Unmarshal(ev.Data, &data); err != nil || data.Delta["text"] != "rest" {
		t.Fatalf("synthetic data = %s (%v), field %s", ev.Data, err, f.Path)
	}
	if !bytes.HasPrefix(raw, []byte("event: content_block_delta\ndata: ")) || !bytes.HasSuffix(raw, []byte("\n\n")) {
		t.Fatalf("synthetic wire form wrong: %q", raw)
	}
	rawJSON := payload.SyntheticDelta(2, payload.DeltaInputJSON, `"x"`)
	ev2, _ := payload.ParseEvent(rawJSON)
	if f2, ok := payload.ReplaceableText(ev2); !ok || !f2.Escaped || f2.Path.String() != "delta.partial_json" {
		t.Fatalf("synthetic input_json_delta = %+v ok=%v", f2, ok)
	}
}
