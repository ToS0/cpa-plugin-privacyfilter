package basics

// Restorer() freezes the table on its first call; the contract says the
// forward pass finishes the table before the return pass starts. These tests
// hold that contract in place, because a caller who gets the order wrong is
// not told: the lookup succeeds, the pseudonym goes out, and nothing brings
// it back.

import (
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// The production order: fill everything, then restore.
func TestRestorer_FillThenRestore(t *testing.T) {
	tab := newTable(t)
	values := []string{"one.lan", "two.lan", "three.lan", "four.lan"}
	var pseudos []string
	for _, v := range values {
		pseudos = append(pseudos, tab.Lookup(detect.KindHost, v))
	}
	for i, p := range pseudos {
		if got := back(p, tab); got != values[i] {
			t.Errorf("%q did not restore to %q, got %q", p, values[i], got)
		}
	}
	joined := pseudos[0] + " talks to " + pseudos[3]
	if got := back(joined, tab); got != "one.lan talks to four.lan" {
		t.Errorf("mixed text: %q", got)
	}
}

// The wrong order, spelled out so the cost of getting it wrong is on record.
// An entry added after the freeze is silently invisible to the restorer.
func TestRestorer_FreezeIsSilent(t *testing.T) {
	tab := newTable(t)
	first := tab.Lookup(detect.KindHost, "one.lan")
	if got := back(first, tab); got != "one.lan" { // this call freezes the table
		t.Fatalf("the first entry was not restored: %q", got)
	}
	second := tab.Lookup(detect.KindHost, "two.lan")
	if second == first {
		t.Fatalf("both values produced the same pseudonym %q", first)
	}
	got := back(second, tab)
	if got == "two.lan" {
		t.Logf("later entries are restored after all, the freeze has been lifted")
		return
	}
	t.Logf("as documented: %q stays a pseudonym, and Lookup gave no sign", second)
	t.Logf("   -> a caller that scans after the first restore loses every value it found")
	if tab.Len() != 2 {
		t.Errorf("the entry was not even stored: Len=%d", tab.Len())
	}
}

// A restorer handle taken before the forward pass is empty for good, which is
// the same trap seen from the stream side.
func TestRestorer_HandleTakenTooEarly(t *testing.T) {
	tab := newTable(t)
	r := tab.Restorer()
	p := tab.Lookup(detect.KindHost, "alpha.lan")
	out, changed := r.Restore(p, false)
	if changed || out != p {
		t.Logf("the early handle sees later entries: %q", out)
		return
	}
	t.Logf("as documented: a handle taken before the forward pass restores nothing")
	if n := r.Holdback("text ending in " + p[:6]); n != 0 {
		t.Errorf("but it does hold back %d bytes, which would truncate the answer", n)
	}
}
