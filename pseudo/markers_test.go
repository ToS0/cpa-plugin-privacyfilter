package pseudo_test

import (
	"testing"

	"privacyfilter/filter"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// Package detect repeats the two ranges of the address pseudonyms, because
// this package imports that one. The test holds the copy equal to the
// ranges the generator uses: each range in CIDR notation passes the
// structural layer and the library wrapper untouched, and the first address
// inside it is still found.
func TestMarkerRangesAreLeftByTheDetectors(t *testing.T) {
	pat, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, CIDR: true})
	if err != nil {
		t.Fatal(err)
	}
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	lib := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true})
	if len(pseudo.MarkerRanges) != 2 {
		t.Fatalf("MarkerRanges has %d entries, want 2", len(pseudo.MarkerRanges))
	}
	for _, m := range pseudo.MarkerRanges {
		text := "route " + m.String() + " via"
		if got := pat.Scan(text); len(got) != 0 {
			t.Errorf("patterns: Scan(%q) = %+v, want nothing", text, got)
		}
		if got := lib.Scan(text); len(got) != 0 {
			t.Errorf("packyme: Scan(%q) = %+v, want nothing", text, got)
		}
		inner := m.Addr().Next().String()
		if got := pat.Scan("node " + inner + " up"); len(got) != 1 || got[0].Value != inner {
			t.Errorf("patterns: Scan(%q) = %+v, want the address", inner, got)
		}
	}
}
