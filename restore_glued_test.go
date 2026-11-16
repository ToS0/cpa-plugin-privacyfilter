package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
)

// gluedSecret puts a secret into tab whose original ends in a space, as a
// credential rule of the library cut it before f74df30, and returns the
// original and two texts: the pseudonym glued to the next word, as the model
// read it in the system prompt of Claude Code, and the pseudonym standing
// alone.
func gluedSecret(tab *mapping.Table) (orig, glued, spaced string) {
	orig = "lab-credential-value-0001 "
	alias := tab.Lookup(detect.KindSecret, orig)
	return orig, "require clear " + alias + "engagements, CTF", "require clear " + alias + " engagements, CTF"
}

// TestRestore_GluedSecretStaysOnEveryPath: a pseudonym glued to a word is
// not restored, on any path a response takes: the whole text in both
// escapings, text deltas cut at every byte, deltas of one rune, a text
// block that arrives filled, a tool_use block whose input arrives in its
// start, input_json_delta cut at every byte, and the non-streamed response.
// The pseudonym standing alone comes back on each of them. The finding "Ein
// Fund der Bibliothek klebt am Wort" saw the original arrive live in three
// write calls; none of these paths produces it.
func TestRestore_GluedSecretStaysOnEveryPath(t *testing.T) {
	tab := lab.Table()
	orig, glued, spaced := gluedSecret(tab)
	r := tab.Restorer()
	check := func(path, text, got string) {
		t.Helper()
		back := strings.Contains(got, orig)
		if text == glued && back {
			t.Errorf("%s: the glued pseudonym was restored: %q", path, got)
		}
		if text == spaced && !back {
			t.Errorf("%s: the pseudonym standing alone was not restored: %q", path, got)
		}
	}

	for _, text := range []string{glued, spaced} {
		for _, esc := range []bool{false, true} {
			got, _ := r.Restore(text, esc)
			check("whole text", text, got)
		}
		for k := 1; k < len(text); k++ {
			st, c := newState(tab), newClient(t)
			run(st, c, evBlockStartText(0, ""), evTextDelta(0, text[:k]), evTextDelta(0, text[k:]), evBlockStop(0), evMessageStop())
			check("text delta cut at "+strconv.Itoa(k), text, c.block(0))
		}

		st, c := newState(tab), newClient(t)
		chunks := append([][]byte{evBlockStartText(0, "")}, deltaChunks(0, text, 1)...)
		run(st, c, append(chunks, evBlockStop(0), evMessageStop())...)
		check("deltas of one rune", text, c.block(0))

		st, c = newState(tab), newClient(t)
		run(st, c, evBlockStartText(0, text), evBlockStop(0), evMessageStop())
		check("filled text block", text, c.block(0))

		st = newState(tab)
		out := st.deliver(evBlockStartRaw(0, `{"type":"tool_use","id":"toolu_lab","name":"Write","input":{"file_path":"/tmp/lab.txt","content":`+jstr(text)+`}}`))
		check("tool_use input in the block start", text, string(out))

		inner, err := json.Marshal(map[string]string{"file_path": "/tmp/lab.txt", "content": text})
		if err != nil {
			t.Fatal(err)
		}
		frag := string(inner)
		for k := 1; k < len(frag); k++ {
			st, c := newState(tab), newClient(t)
			run(st, c,
				evBlockStartRaw(0, `{"type":"tool_use","id":"toolu_lab","name":"Write","input":{}}`),
				evJSONDelta(0, frag[:k]), evJSONDelta(0, frag[k:]),
				evBlockStop(0), evMessageStop())
			var input map[string]string
			if err := json.Unmarshal([]byte(c.block(0)), &input); err != nil {
				t.Errorf("input_json_delta cut at %d: the assembled input is not JSON: %v", k, err)
				continue
			}
			check("input_json_delta", text, input["content"])
		}
	}

	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, "lab-session")
	beforeAuth(t, p, "req-1", body)
	orig, glued, spaced = gluedSecret(p.tableOf(t, "req-1"))
	for _, text := range []string{glued, spaced} {
		resp := `{"id":"msg_01","type":"message","role":"assistant","model":"claude-fable-5-1","content":[` +
			`{"type":"text","text":` + jstr(text) + `},` +
			`{"type":"tool_use","id":"toolu_lab","name":"Write","input":{"file_path":"/tmp/lab.txt","content":` + jstr(text) + `}}],` +
			`"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`
		got := interceptResponse(t, p, "req-1", "claude", []byte(resp))
		if text == glued && bytes.Contains(got.Body, []byte(orig)) {
			t.Errorf("non-streamed response: the glued pseudonym was restored: %s", got.Body)
		}
		if text == spaced && (len(got.Body) == 0 || bytes.Count(got.Body, []byte(orig)) != 2) {
			t.Errorf("non-streamed response: the pseudonym standing alone was not restored in both blocks: %s", got.Body)
		}
	}
}
