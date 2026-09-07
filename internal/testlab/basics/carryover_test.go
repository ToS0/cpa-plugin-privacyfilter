package basics

// A pseudonym that reaches the client unresolved becomes ordinary text in the
// conversation, and from then on the original never appears again: the
// forward pass skips it, because the composite excludes anything shaped like
// a pseudonym, so it is never entered into the table, so the return pass has
// nothing to resolve it with. The error feeds itself.
//
// This is not theory. It happened in this very session: a command written as
// "./payload" came back with the pseudonym in its place and failed with "no
// such package".

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

func gen(t *testing.T) *pseudo.Generator {
	t.Helper()
	return pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
}

// Request one carries the value, request two carries only the pseudonym the
// model wrote back. The second request cannot restore it.
func TestCarry_PseudonymInTheHistoryIsNotResolvable(t *testing.T) {
	skipOpenFinding(t)
	g := gen(t)
	terms := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	comp := detect.NewComposite(g.IsPseudonym, terms)

	// Request one: the value is in the text, the table learns it.
	first := mapping.NewTable(g)
	sent := forward("der Dienst läuft auf zeus.lan", comp, first)
	alias := first.Lookup(detect.KindHost, "zeus.lan")
	if !strings.Contains(sent, alias) {
		t.Fatalf("the forward pass did not use the table's pseudonym: %q", sent)
	}
	// The answer comes back and is restored, so far so good.
	if got := back("ich sehe "+alias, first); !strings.Contains(got, "zeus.lan") {
		t.Fatalf("request one did not restore: %q", got)
	}

	// Request two: the history now contains the model's own answer. Suppose
	// one of them was not restored - through an expired table, an evicted
	// one, or a pseudonym the model reshaped - so the history carries the
	// pseudonym as plain text.
	second := mapping.NewTable(g)
	history := "vorhin sagtest du: ich sehe " + alias
	sentAgain := forward(history, comp, second)
	if sentAgain != history {
		t.Logf("the second request rewrote the history: %q", sentAgain)
	}
	t.Logf("entries in the second table: %d", second.Len())
	if second.Len() != 0 {
		t.Logf("the pseudonym was entered after all")
	}

	// The model repeats it, as models do, and now nothing resolves it.
	answer := "dann prüfe ich " + alias
	got := back(answer, second)
	if strings.Contains(got, alias) {
		t.Errorf("the pseudonym reaches the client as text: %q", got)
		t.Logf("   -> from here it is written into files and run as a command")
	}
}

// The same table, on the other hand, resolves it: a session-wide table would
// not have this problem. Recorded as the shape of a possible cure.
func TestCarry_SameTableStillResolves(t *testing.T) {
	g := gen(t)
	tab := mapping.NewTable(g)
	alias := tab.Lookup(detect.KindHost, "zeus.lan")
	if got := back("prüfe "+alias, tab); got != "prüfe zeus.lan" {
		t.Errorf("even the same table failed: %q", got)
	}
}

// How a pseudonym gets into the history in the first place: three ways, all
// of them seen in this session.
func TestCarry_WaysIntoTheHistory(t *testing.T) {
	g := gen(t)
	tab := mapping.NewTable(g)
	alias := tab.Lookup(detect.KindHost, "zeus.lan")

	t.Run("table gone", func(t *testing.T) {
		empty := mapping.NewTable(g)
		if got := back(alias, empty); got != alias {
			t.Errorf("unexpected: %q", got)
		}
		t.Logf("an expired or evicted table leaves %q standing", alias)
	})

	t.Run("model reshaped it", func(t *testing.T) {
		cut := alias[:len(alias)-1]
		if got := back(cut, tab); got != cut {
			t.Errorf("unexpected: %q", got)
		}
		t.Logf("a shortened pseudonym %q cannot be resolved and stays", cut)
	})

	t.Run("model invented it", func(t *testing.T) {
		invented := "h-" + strings.Repeat("a", 12)
		if got := back(invented, tab); got != invented {
			t.Errorf("an invented pseudonym was resolved: %q", got)
		}
		t.Logf("an invented %q passes through, as the contract requires", invented)
	})
}
