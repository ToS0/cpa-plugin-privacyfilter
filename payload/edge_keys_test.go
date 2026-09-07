package payload_test

// Keys at their edges: a key that appears twice, a key without a name, a key
// of 64 kibibytes, an object with thousands of them, and the key as a place
// where text lives at all.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// A key without a name is legal JSON. It must not confuse the path, and the
// value behind it must be filtered like any other.
func TestJSONEdge_EmptyKeyName(t *testing.T) {
	body := fmt.Sprintf(`{"":%q,"a":{"":%q},"hit":%q}`, needle, needle, needle)
	fwd, ret := checkBoth(t, body)
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		if leaked(out) {
			t.Errorf("%s: a value behind a nameless key was not replaced: %s", name, out)
		}
	}
	paths, err := visitedOut(body)
	if err != nil {
		t.Fatalf("visitedOut: %v", err)
	}
	t.Logf("paths with a nameless key: %q", paths)
}

// A key of 64 kibibytes. Nothing in the walk bounds a key, so this only asks
// whether the body survives it.
func TestJSONEdge_VeryLongKey(t *testing.T) {
	key := strings.Repeat("k", 64<<10)
	body := fmt.Sprintf(`{%q:%q,"hit":%q}`, key, needle, needle)
	fwd, ret := checkBoth(t, body)
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		if leaked(out) {
			t.Errorf("%s: the value behind the long key was not replaced", name)
		}
		if !bytes.Contains(out, []byte(key)) {
			t.Errorf("%s: the long key did not survive", name)
		}
	}
}

// An object with five thousand keys, every two hundred and fiftieth carrying
// the value, and an array of the same width beside it.
func TestJSONEdge_WideObject(t *testing.T) {
	const width = 5000
	var b strings.Builder
	b.WriteString(`{"wide":{`)
	hits := 0
	for i := 0; i < width; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		value := "plain"
		if i%250 == 0 {
			value = needle
			hits++
		}
		fmt.Fprintf(&b, `%q:%q`, fmt.Sprintf("key_%04d", i), value)
	}
	b.WriteString(`},"list":[`)
	for i := 0; i < width; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%q`, "plain")
	}
	b.WriteString(`]}`)
	body := b.String()

	fwd, ret := checkBoth(t, body)
	if leaked(fwd) || leaked(ret) {
		t.Errorf("a value inside the wide object was missed")
	}
	_, n, err := inbound(body)
	if err != nil {
		t.Fatalf("return: %v", err)
	}
	if n != hits {
		t.Errorf("the return path replaced %d of %d values in the wide object", n, hits)
	}
	t.Logf("width=%d hits=%d body=%d bytes forward=%d bytes", width, hits, len(body), len(fwd))
}

// Both directions must see the same set of fields; where they do not, a body
// is filtered differently on the way out than on the way back.
func TestJSONEdge_BothDirectionsSeeTheSameFields(t *testing.T) {
	body := fmt.Sprintf(`{"model":"claude","system":[{"type":"text","text":%q}],`+
		`"messages":[{"role":"user","content":[`+
		`{"type":"text","text":%q},`+
		`{"type":"thinking","thinking":"reasoning","signature":"sig"},`+
		`{"type":"tool_use","id":"toolu_01","name":%q,"input":{"path":%q,"name":%q}},`+
		`{"type":"tool_result","tool_use_id":"toolu_01","content":[`+
		`{"type":"text","text":%q},`+
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}],`+
		`"metadata":{"user_id":"u1"},"tools":[{"name":%q,"description":%q}]}`,
		needle, needle, alias, needle, needle, needle, alias, needle)

	out, err := visitedOut(body)
	if err != nil {
		t.Fatalf("visitedOut: %v", err)
	}
	in, err := visitedIn(body)
	if err != nil {
		t.Fatalf("visitedIn: %v", err)
	}
	sort.Strings(out)
	sort.Strings(in)
	t.Logf("forward sees %d fields: %q", len(out), out)
	t.Logf("return sees  %d fields: %q", len(in), in)
	if strings.Join(out, "\n") != strings.Join(in, "\n") {
		t.Errorf("the two directions disagree about which fields are filtered")
	}
}

// A string is not the only place text lives; the walk must at least not lose
// a key while it writes the body back. Checked over a body whose keys need
// escaping.
func TestJSONEdge_KeysThatNeedEscaping(t *testing.T) {
	keys := []string{"a\"b", "a\\b", "a\nb", "a\tb", "ü", " ", "a/b", "a.b"}
	var b strings.Builder
	b.WriteByte('{')
	for _, k := range keys {
		enc, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		b.Write(enc)
		b.WriteString(`:"plain",`)
	}
	fmt.Fprintf(&b, `"hit":%q}`, needle)
	body := b.String()

	fwd, ret := checkBoth(t, body)
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%s: the key %q was lost", name, k)
			}
		}
	}
}
