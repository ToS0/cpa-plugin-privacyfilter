package mapping_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// A network of the length of a marker range, an IPv4 /10 or an IPv6 /48, is
// rendered as that range on every attempt. The forward pass leaves the range
// itself in the clear, so the table must not hand it out: the way back would
// turn every mention of the range into the network. The network gets the
// range with the collision suffix, and two such networks get two suffixes.
// The values are built from numbers.
func TestLookup_NeverHandsOutAMarkerRange(t *testing.T) {
	gen := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
	tab := mapping.NewTable(gen)
	networks := []string{
		netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 64, 0, 0}), 10).String(),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 128, 0, 0}), 10).String(),
		netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a}), 48).String(),
	}
	seen := map[string]bool{}
	for _, network := range networks {
		got := tab.Lookup(detect.KindCIDR, network)
		bare, suffix, ok := strings.Cut(got, "#")
		if !ok || suffix == "" || !detect.IsMarkerRange(bare) {
			t.Errorf("Lookup(%s) = %q, want a marker range with the collision suffix", network, got)
		}
		if seen[got] {
			t.Errorf("Lookup(%s) = %q, handed out twice", network, got)
		}
		seen[got] = true
		if e, ok := tab.Original(got); !ok || e.Original != network {
			t.Errorf("Original(%q) = %+v, %v, want %s", got, e, ok, network)
		}
	}
}
