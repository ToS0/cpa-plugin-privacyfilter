package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// luhnRun appends the check digit that makes prefix pass the Luhn test, so
// the library reports the run as a bank card without a literal number in
// the source.
func luhnRun(prefix string) string {
	for d := 0; d < 10; d++ {
		s := prefix + strconv.Itoa(d)
		sum, double := 0, false
		for i := len(s) - 1; i >= 0; i-- {
			x := int(s[i] - '0')
			if double {
				if x *= 2; x > 9 {
					x -= 9
				}
			}
			sum += x
			double = !double
		}
		if sum%10 == 0 {
			return s
		}
	}
	return ""
}

// TestRoundTrip_FindingsTouchingAWordComeBack: the forward pass must write
// a pseudonym only where the return path restores it. The library bounds
// its digit rules by digits alone and lets a gitleaks rule end on the space
// behind the value, so a Luhn-valid run inside a file name and a credential
// followed by a word got pseudonyms glued to a word; the model repeated
// them, and the return path, which restores nothing that continues a word,
// handed them to the client as they were, in the whole response and in the
// stream alike, and counted them nowhere. Each case is sent through the
// forward pass, echoed by the model exactly as it saw it, and has to come
// back whole, at every split point of a two-fragment stream too.
func TestRoundTrip_FindingsTouchingAWordComeBack(t *testing.T) {
	num := luhnRun("176190000000")
	cases := []struct {
		name, text, secret string
	}{
		{"spaced", "Zeitstempel " + num + " im Log", num},
		{"glued", "Datei foto" + num + "x.jpg liegt dort", num},
		{"credential", "require clear authorization context: pentesting engagements, CTF competitions", "pentesting"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPseudoPlugin(t, nil)
			req := map[string]any{
				"model":      "claude-fable-5-1",
				"max_tokens": 10,
				"messages": []any{map[string]any{
					"role":    "user",
					"content": []any{map[string]any{"type": "text", "text": tc.text}},
				}},
			}
			body, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			resp := beforeAuth(t, p, "req-"+tc.name, body)
			if len(resp.Body) == 0 {
				t.Fatal("the forward pass replaced nothing")
			}
			var fwd struct {
				Messages []struct {
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"messages"`
			}
			if err := json.Unmarshal(resp.Body, &fwd); err != nil {
				t.Fatal(err)
			}
			sent := fwd.Messages[0].Content[0].Text
			if strings.Contains(sent, tc.secret) {
				t.Fatalf("the value left in clear text: %q", sent)
			}

			upstream := `{"id":"msg_01","type":"message","role":"assistant","model":"claude-fable-5-1",` +
				`"content":[{"type":"text","text":` + string(jsonString(t, sent)) + `}],` +
				`"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`
			r := interceptResponse(t, p, "req-"+tc.name, "claude", []byte(upstream))
			var back struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			}
			if len(r.Body) == 0 {
				t.Fatalf("the response came back unrestored: %q", sent)
			}
			if err := json.Unmarshal(r.Body, &back); err != nil {
				t.Fatal(err)
			}
			if back.Content[0].Text != tc.text {
				t.Fatalf("response restored to %q, want %q", back.Content[0].Text, tc.text)
			}

			table := p.tableOf(t, "req-"+tc.name)
			for i := 1; i < len(sent); i++ {
				st, c := newState(table), newClient(t)
				run(st, c, sseMessageStart("claude-fable-5-1"), evBlockStartText(0, ""),
					evTextDelta(0, sent[:i]), evTextDelta(0, sent[i:]), evBlockStop(0),
					evMessageDelta("end_turn", 1))
				if got := c.block(0); got != tc.text {
					t.Fatalf("text_delta split at %d restored to %q, want %q", i, got, tc.text)
				}

				doc := `{"content":` + jstr(sent) + `}`
				cut := strings.Index(doc, sent) + i
				st, c = newState(table), newClient(t)
				run(st, c, sseMessageStart("claude-fable-5-1"),
					evBlockStartRaw(0, `{"type":"tool_use","id":"toolu_boundary","name":"Write","input":{}}`),
					evJSONDelta(0, doc[:cut]), evJSONDelta(0, doc[cut:]), evBlockStop(0),
					evMessageDelta("tool_use", 1))
				var in struct {
					Content string `json:"content"`
				}
				if err := json.Unmarshal([]byte(c.block(0)), &in); err != nil || in.Content != tc.text {
					t.Fatalf("input_json_delta split at %d restored to %q (%v), want %q", i, in.Content, err, tc.text)
				}
			}
		})
	}
}
