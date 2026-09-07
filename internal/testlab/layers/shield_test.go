package layers

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// Exclude is applied to every layer, the maintained term list included, so a
// term whose value carries the shape of a pseudonym is dropped like any other
// match of that shape: an address out of the marker range the address
// pseudonyms live in, a hardware address out of the locally administered
// range the MAC pseudonyms live in. That is the documented rule and it is no
// hole in the term list, because the other half of it sits in the wiring: the
// plugin refuses such a term while it reads the configuration and names the
// value in the error, so a term the composite would ignore never reaches a
// running filter. The address renderer states the requirement; this test
// holds the half the detect package answers for.
func TestLayers_ATermThatLooksLikeAPseudonymIsDropped(t *testing.T) {
	g := lab.Gen()
	addr := lab.V4(100, 100, 20, 5)
	mac := lab.MAC(0x02, 0x42, 0xac, 0x11, 0x00, 0x02)
	if !g.IsPseudonym(addr) || !g.IsPseudonym(mac) {
		t.Fatalf("the probes do not have the shape of a pseudonym; the ranges have moved")
	}

	terms := lab.Terms(t,
		detect.Term{Value: addr, Kind: detect.KindIPv4},
		detect.Term{Value: mac, Kind: detect.KindMAC},
	)
	text := "ssh " + addr + " hw " + mac
	c := detect.NewComposite(g.IsPseudonym, terms)
	if got := c.Scan(text); got != nil {
		t.Fatalf("composite = %s, want nothing: both term hits carry the shape of a pseudonym", where(got))
	}
	if out := roundTrip(t, text, c); out != text {
		t.Fatalf("the outbound text changed although every hit was excluded")
	}
}

// The same value under a kind of its own: the shape test asks every renderer
// and does not read the declared kind, so a term is dropped whatever kind it
// carries. The wiring's refusal is kind-agnostic for the same reason, so
// nothing gets past it through a mislabelled kind either.
func TestLayers_TheShapeTestIgnoresTheDeclaredKind(t *testing.T) {
	g := lab.Gen()
	addr := lab.V4(100, 100, 20, 6)
	terms := lab.Terms(t, detect.Term{Value: addr, Kind: detect.KindHost})
	text := "ssh " + addr
	if got := detect.NewComposite(g.IsPseudonym, terms).Scan(text); got != nil {
		t.Fatalf("composite = %s, want nothing reported", where(got))
	}
	t.Logf("a term of kind %q whose value has the shape of an %q pseudonym is dropped",
		detect.KindHost, detect.KindIPv4)
}

// An excluded hit keeps its rank and shields its span against the later
// layers. That is what keeps a second forward pass a no-op. It also means
// that a real value which merely looks like a pseudonym protects everything
// around it that a later layer would have replaced: here the customer
// directory that carries the address in its name.
func TestLayers_AnExcludedHitShieldsTheSegmentAroundIt(t *testing.T) {
	skipOpenFinding(t)
	g := lab.Gen()
	addr := lab.V4(100, 100, 20, 7)
	customer := dir(12)
	segment := customer + "-" + addr
	text := abs("mnt", segment, "data")

	patterns := lab.Patterns(t, detect.PatternsConfig{IPv4: true})
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})

	// The path net alone protects the whole segment: its value is the
	// segment, and that is not the shape of any pseudonym.
	alone := detect.NewComposite(g.IsPseudonym, paths)
	if got := alone.Scan(text); len(got) != 1 || got[0].Value != segment {
		t.Fatalf("path layer alone = %q, want the whole segment", spans(got))
	}
	if out := roundTrip(t, text, alone); strings.Contains(out, customer) {
		t.Fatalf("the path layer alone leaves the directory name in the text")
	}

	// With the structural layer in front, its hit on the address is excluded
	// and shields the segment, so nothing at all is replaced.
	c := detect.NewComposite(g.IsPseudonym, patterns, paths)
	if got := c.Scan(text); got != nil {
		t.Fatalf("composite = %q, want nothing reported", spans(got))
	}
	out := roundTrip(t, text, c)
	if strings.Contains(out, customer) {
		t.Fatalf("the excluded address shields the segment: the directory name of %d bytes leaves in the clear", len(customer))
	}
}

// The person kind shows that the term list can be honoured: the plugin
// builds its renderers from the list, a name on it leaves the pool, and the
// shape test then no longer claims it. The address and MAC kinds have no
// such door.
func TestLayers_ThePersonKindAlreadyHonoursTheTermList(t *testing.T) {
	g := lab.Gen()
	name := g.Pseudonym(detect.KindPerson, node(13), 0)
	if !g.IsPseudonym(name) {
		t.Fatalf("a name out of the pool is not recognised as a pseudonym")
	}

	renderers, dropped := pseudo.RenderersExcludingNames([]string{name})
	if len(dropped) != 1 {
		t.Fatalf("RenderersExcludingNames dropped %d entries, want 1", len(dropped))
	}
	g2 := pseudo.NewGenerator([]byte(lab.Secret), []byte(lab.Salt), renderers)
	if g2.IsPseudonym(name) {
		t.Fatalf("a name taken out of the pool is still claimed by the shape test")
	}

	terms := lab.Terms(t, detect.Term{Value: name, Kind: detect.KindPerson})
	text := "call " + name + " back"
	got := detect.NewComposite(g2.IsPseudonym, terms).Scan(text)
	if len(got) != 1 || got[0].Kind != detect.KindPerson {
		t.Fatalf("composite reported %d hits, want the term hit", len(got))
	}
	if out := roundTrip(t, text, detect.NewComposite(g2.IsPseudonym, terms)); strings.Contains(out, name) {
		t.Fatalf("the listed name leaves in the clear")
	}
}

// An excluded match is dropped by the composite that produced it, so a
// composite used as a layer of another composite no longer shields its
// span. The plugin builds one flat composite; this is a note for whoever
// nests them.
func TestLayers_NestedCompositeLosesTheShield(t *testing.T) {
	g := lab.Gen()
	p := g.Pseudonym(detect.KindHost, node(14), 0)
	text := "key " + p + " end"
	narrow := fakeLayer{"narrow", detect.KindHost, [][2]int{{4, 4 + len(p)}}}
	wide := fakeLayer{"wide", detect.KindSecret, [][2]int{{0, len(text)}}}

	if got := detect.NewComposite(g.IsPseudonym, narrow, wide).Scan(text); got != nil {
		t.Fatalf("flat composite reported %d hits, want the wide match shielded", len(got))
	}
	nested := detect.NewComposite(g.IsPseudonym, detect.NewComposite(g.IsPseudonym, narrow), wide)
	got := nested.Scan(text)
	if len(got) != 1 || got[0].Source != "wide" {
		t.Fatalf("nested composite = %q from %q", spans(got), sources(got))
	}
	t.Logf("nested in a second composite the excluded hit no longer shields its span")
}
