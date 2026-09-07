package props

// A term declared as a network whose value has a slash but no address in
// front of it. Generator.Pseudonym composes a cidr pseudonym out of an
// address pseudonym and the prefix length as written. When the address part
// is neither an address nor a wildcard quad, the address renderer falls back
// to the opaque token, and the composed result reads "PF_<hex>/24" - a shape
// no renderer knows, so the generator's own IsPseudonym rejects what the
// generator wrote.
//
// The wiring does not stop it either: main.go tries netip.ParsePrefix on a
// cidr term only to collect the networks whose structure is kept, and a value
// that does not parse is simply not collected. The fuzzer found it in
// FuzzPropsPseudonymShape.

import (
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// brokenWildcards are values a hand-written list plausibly carries under kind
// cidr: the short form of a whole net, and a typo in place of the address.
func brokenWildcards() []string {
	return []string{
		"*/24",
		"10.*/24",
		"netz*/24",
		"0*00000/0",
	}
}

// The generator's own output has to be recognised as a pseudonym.
func TestProps_CidrTermWithABrokenWildcard(t *testing.T) {
	skipOpenFinding(t)
	gen := lab.Gen()
	for _, value := range brokenWildcards() {
		p := gen.Pseudonym(detect.KindCIDR, value, 0)
		if !gen.IsPseudonym(p) {
			t.Errorf("the cidr term %q renders to %q, which IsPseudonym does not know", value, p)
		}
	}
}

// The counter-probes. A value with no slash at all falls back to the opaque
// token whole, which is a shape of its own; a network and a well-formed
// wildcard quad both render to something the exclude knows.
func TestProps_CidrTermShapesTheGeneratorKnows(t *testing.T) {
	gen := lab.Gen()
	values := []string{
		"kundennetz",
		"netz/24",
		lab.V4(10, 0, 0, 0) + "/",
		lab.V4(10, 0, 0, 0) + "/8",
		lab.V4(192, 168, 1, 0) + "/24",
		lab.V4(10, 0, 0, 256) + "/24",
		"10.0.*.0/24",
		"fd00::/8",
	}
	for _, value := range values {
		p := gen.Pseudonym(detect.KindCIDR, value, 0)
		if !gen.IsPseudonym(p) {
			t.Errorf("the cidr term %q renders to %q, which IsPseudonym does not know", value, p)
		}
	}
}
