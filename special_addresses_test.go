package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
)

// v4 builds an IPv4 address from its octets, so this file holds no dotted
// quad that the filter of a session could rewrite on its way to disk.
func v4(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }

// marker4 and marker6 are the two ranges of the address pseudonyms in CIDR
// notation; package pseudo holds the detectors to its own copies.
func marker4() string { return v4(100, 64, 0, 0) + "/10" }
func marker6() string {
	return netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0xff, 0x50, 0x46, 0x53, 0x46}), 48).String()
}

// TestPseudonymizeRequest_SpecialAddressesSurviveEveryLayer runs the forward
// path with the library layer on, as the server runs it. Loopback, a
// documentation address and the two ranges of the address pseudonyms in
// CIDR notation leave as they are; until the library wrapper asked the same
// question as the structural layer, the library replaced the first two and
// the address part of the third. An address inside the marker range is
// replaced like any other.
func TestPseudonymizeRequest_SpecialAddressesSurviveEveryLayer(t *testing.T) {
	kept := []string{v4(127, 0, 0, 1), v4(192, 0, 2, 10), marker4(), marker6()}
	inner := v4(100, 64+9, 3, 4)
	content := "bind " + kept[0] + ", docs " + kept[1] + ", route " + marker4() + " and " + marker6() + ", peer " + inner + "."
	body, err := json.Marshal(map[string]any{
		"model":    "claude-fable-5-1",
		"messages": []any{map[string]any{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	p := newPseudoPlugin(t, nil)
	resp := beforeAuth(t, p, "req-1", body)
	if resp.Terminate {
		t.Fatalf("request terminated: %s", resp.ResponseBody)
	}
	out := string(resp.Body)
	if out == "" {
		t.Fatal("body not rewritten, but the address inside the marker range should have been replaced")
	}
	for _, s := range kept {
		if !strings.Contains(out, s) {
			t.Errorf("%s was replaced, body: %s", s, out)
		}
	}
	if strings.Contains(out, inner) {
		t.Errorf("the address inside the marker range left unchanged, body: %s", out)
	}
}

// TestPseudonymizeRequest_SecondPassIsQuietOverASuffixedPseudonym: an IPv4
// network of length 10 can only be rendered as the marker range itself,
// because every attempt masks back onto the range, and the table hands out
// no pseudonym that equals a marker range, since the forward pass leaves
// the range in the clear and the way back could not tell the two apart. The
// network gets the range with the collision suffix, in which the range
// stands as a prefix with the "#" for a boundary. A second pass over the
// output, in the hook after authentication or as the next request, used to
// see that prefix as a network and append the suffix once more, five bytes
// every pass, as the log of the 7th of October showed. Until the marker
// ranges were exempt, the text that produced the suffix was the range
// itself, named in a note about the plugin; it now stays as it is next to
// the suffixed pseudonym.
func TestPseudonymizeRequest_SecondPassIsQuietOverASuffixedPseudonym(t *testing.T) {
	marker := marker4()
	network := v4(10, 64, 0, 0) + "/10"
	suffixed := marker + "#1024"
	note := "The range " + marker + " marks the pseudonyms,"
	p := newPseudoPlugin(t, nil)
	_, req := fixtureBody(t, fixtures.SessionA)
	req["messages"] = []any{map[string]any{"role": "user", "content": note + " the office has " + network + "."}}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	first := beforeAuth(t, p, "req-1", body)
	if first.Terminate || first.Body == nil {
		t.Fatalf("the first pass did not rewrite: %+v", first)
	}
	table := p.tableOf(t, "req-1")
	if table.Has(detect.KindCIDR, marker) {
		t.Fatal("the marker range got a row, but it should leave as it is")
	}
	if !table.Has(detect.KindCIDR, network) {
		t.Fatal("the pattern layer did not report the network")
	}
	if got := table.Lookup(detect.KindCIDR, network); got != suffixed {
		t.Fatalf("the network got the pseudonym %q, want the marker range with the collision suffix", got)
	}
	out := string(first.Body)
	if !strings.Contains(out, note) {
		t.Fatalf("the marker range in the note was rewritten:\n%s", out)
	}
	if strings.Contains(out, network) {
		t.Fatalf("the network left unchanged:\n%s", out)
	}
	if strings.Count(out, suffixed) != 1 || strings.Contains(out, suffixed+"#") {
		t.Fatalf("the first pass wrote the suffixed pseudonym %d times or doubled it:\n%s", strings.Count(out, suffixed), out)
	}
	rows := table.Len()

	if again := afterAuth(t, p, "req-1", first.Body); again.Body != nil {
		t.Fatalf("the second hook changed the body:\n%s", again.Body)
	}
	if next := beforeAuth(t, p, "req-2", first.Body); next.Body != nil && !bytes.Equal(next.Body, first.Body) {
		t.Fatalf("the next request changed the body:\n%s", next.Body)
	}
	if got := table.Len(); got != rows {
		t.Fatalf("the second passes grew the table from %d to %d rows", rows, got)
	}
}
