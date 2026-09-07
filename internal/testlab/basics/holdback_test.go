package basics

// Probes for the streaming hold-back. stream.go itself is package main and
// cannot be imported, but the mechanism lives in mapping.Restorer and is
// reachable from outside: append to what is pending, ask how much of the
// tail must wait, emit and restore the rest.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
)

func streamRestore(t *testing.T, chunks []string, r mapping.Restorer) string {
	t.Helper()
	var out strings.Builder
	pending := ""
	for _, c := range chunks {
		pending += c
		h := r.Holdback(pending)
		if h < 0 || h > len(pending) {
			t.Fatalf("Holdback(%q) = %d, out of range", pending, h)
		}
		emit := pending[:len(pending)-h]
		pending = pending[len(pending)-h:]
		if !utf8.ValidString(emit) {
			t.Errorf("hold-back split a UTF-8 sequence: emitted %q", emit)
		}
		restored, _ := r.Restore(emit, false)
		out.WriteString(restored)
	}
	restored, _ := r.Restore(pending, false)
	out.WriteString(restored)
	return out.String()
}

// tableWithValues fills a table with several kinds and returns the aliases in
// the order the values were entered.
func tableWithValues(t *testing.T) (*mapping.Table, []string) {
	t.Helper()
	tab := newTable(t)
	vals := []struct {
		k detect.Kind
		v string
	}{
		{detect.KindHost, "zeus.lan"},
		{detect.KindHost, "hera.lan"},
		{detect.KindHost, "ares.lan"},
		{detect.KindPerson, "Bertha Schmitt"},
		{detect.KindEmail, "b.schmitt@beispiel.example"},
		{detect.KindDomain, "beispiel.example"},
		{detect.KindPathSegment, "kunde-x"},
		{detect.KindUUID, "3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
	}
	var ps []string
	for _, v := range vals {
		p := tab.Lookup(v.k, v.v)
		if p == "" {
			t.Fatalf("empty pseudonym for %s %q", v.k, v.v)
		}
		ps = append(ps, p)
	}
	return tab, ps
}

// Splitting anywhere must not change the result. This is the property the
// hold-back exists for.
func TestHoldback_SplitAtEveryPosition(t *testing.T) {
	skipOpenFinding(t)
	tab, ps := tableWithValues(t)
	r := tab.Restorer()

	// Aliases back to back, so the tail of one can start another, and with
	// ordinary text around them.
	texts := []string{
		strings.Join(ps, ""),
		strings.Join(ps, " "),
		"Host " + ps[0] + ps[1] + " und " + ps[2] + ".",
		ps[3] + " schrieb an " + ps[4] + " über " + ps[5] + "/" + ps[6],
		"Ende mit einem vollständigen Wert: " + ps[7],
	}

	for _, text := range texts {
		want, _ := r.Restore(text, false)
		for i := 1; i < len(text); i++ {
			got := streamRestore(t, []string{text[:i], text[i:]}, r)
			if got != want {
				t.Fatalf("split at %d of %q:\n got %q\nwant %q", i, text, got, want)
			}
		}
	}
}

// Three chunks, byte by byte, over a shorter text: the same property under
// more fragmentation.
func TestHoldback_ByteByByte(t *testing.T) {
	skipOpenFinding(t)
	tab, ps := tableWithValues(t)
	r := tab.Restorer()
	text := "a" + ps[0] + "b" + ps[1] + "c"
	want, _ := r.Restore(text, false)

	chunks := make([]string, 0, len(text))
	for i := 0; i < len(text); i++ {
		chunks = append(chunks, text[i:i+1])
	}
	if got := streamRestore(t, chunks, r); got != want {
		t.Errorf("byte-by-byte:\n got %q\nwant %q", got, want)
	}
}

// The hold-back must be bounded: it may never grow with the length of the
// text, or a stream would stall.
func TestHoldback_BoundedByLongestPseudonym(t *testing.T) {
	tab, ps := tableWithValues(t)
	r := tab.Restorer()
	max := tab.MaxPseudonymLen()

	long := strings.Repeat("x", 5000) + ps[0][:len(ps[0])-1]
	if h := r.Holdback(long); h >= max {
		t.Errorf("Holdback on a 5000 byte text = %d, must be below MaxPseudonymLen %d", h, max)
	}
	if h := r.Holdback(strings.Repeat("y", 5000)); h != 0 {
		t.Errorf("Holdback on text without any prefix = %d, want 0", h)
	}
}

// Multi-byte characters immediately before the hold-back window are where a
// naive byte count cuts a rune in half.
func TestHoldback_NeverSplitsRunes(t *testing.T) {
	tab, ps := tableWithValues(t)
	r := tab.Restorer()
	for _, tail := range []string{"", "ü", "äöü", "😀", "München"} {
		text := "Text " + tail + ps[0][:len(ps[0])-2]
		h := r.Holdback(text)
		emit := text[:len(text)-h]
		if !utf8.ValidString(emit) {
			t.Errorf("tail %q: emitted %q is not valid UTF-8", tail, emit)
		}
	}
}
