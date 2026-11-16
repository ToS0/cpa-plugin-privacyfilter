package detect_test

import (
	"testing"

	"privacyfilter/filter"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// markerV4 and markerV6 are the two ranges of the address pseudonyms in CIDR
// notation, built from numbers like everything in this directory. A test of
// package pseudo holds the detectors to the ranges the generator really
// uses; these here cover the edges of the rule.
func markerV4() string { return q(100, 64, 0, 0) + "/10" }
func markerV6() string { return q6(0xfdff, 0x5046, 0x5346) + "/48" }

// The two ranges, written whole, are left alone by the structural layer
// under every combination of its address switches, and the address that
// opens such a notation is not reported on its own either, so no layer
// leaves a lone prefix length behind.
func TestPatterns_MarkerRangesUntouched(t *testing.T) {
	for _, cfg := range []detect.PatternsConfig{
		{IPv4: true, IPv6: true, CIDR: true},
		{IPv4: true, IPv6: true},
		{CIDR: true},
	} {
		d, err := detect.NewPatterns(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{markerV4(), markerV6()} {
			for _, text := range []string{"route " + s + " via", `"` + s + `"`, s} {
				if got := d.Scan(text); len(got) != 0 {
					t.Errorf("%+v: Scan(%q) = %+v, want nothing", cfg, text, got)
				}
			}
		}
	}
}

// Only the exact notation is exempt. An address inside a range, the network
// address without its length, another length, a host address with the
// range's length and the mask notation are reported as before.
func TestPatterns_NearMarkerRangesFound(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, CIDR: true})
	if err != nil {
		t.Fatal(err)
	}
	found := []string{
		q(100, 64+9, 3, 4),
		q(100, 64, 0, 0),
		q(100, 64, 0, 0) + "/11",
		q(100, 64, 0, 1) + "/10",
		q(100, 64, 0, 0) + "/" + q(255, 192, 0, 0),
		q6(0xfdff, 0x5046, 0x5346, 0, 0, 0, 0, 9),
		q6(0xfdff, 0x5046, 0x5346) + "/47",
		q6(0xfdff, 0x5046, 0x5346, 7) + "/64",
	}
	for _, s := range found {
		if got := d.Scan("route " + s + " via"); len(got) != 1 || got[0].Value != s {
			t.Errorf("Scan(%q) = %+v, want the value itself", s, got)
		}
	}
	inner := q(100, 64+9, 3, 4)
	line := "allow " + markerV4() + " and " + markerV6() + " but not " + inner
	if got := d.Scan(line); len(got) != 1 || got[0].Value != inner {
		t.Fatalf("Scan(%q) = %+v, want only %s", line, got, inner)
	}
}

// The library has no notion of an address that names nothing and runs after
// the structural layer, so without its own check it replaced what that layer
// left: loopback, the unspecified address, a documentation address and the
// address part of a marker range. Ordinary addresses, one inside the marker
// range among them, are still reported.
func TestPackyme_LeavesWhatTheStructuralLayerLeaves(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	d := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true})
	inner, node := q(100, 64+9, 3, 4), q(10, 0, 0, 5)
	text := "bind " + q(127, 0, 0, 1) + " and " + q(0, 0, 0, 0) + ", docs " + q(192, 0, 2, 10) +
		", route " + markerV4() + ", peer " + inner + ", node " + node
	got := d.Scan(text)
	if len(got) != 2 || got[0].Value != inner || got[1].Value != node {
		t.Fatalf("Scan = %+v, want only %s and %s", got, inner, node)
	}
}
