package detect_test

import (
	"strings"
	"testing"

	"privacyfilter/filter"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// fakeKeyBlock builds a private key block from invented base64 lines. The
// header is assembled at run time, so this file holds no key and no line a
// scanner would take for one.
func fakeKeyBlock(lines int) string {
	nl := string(rune(10))
	var b strings.Builder
	b.WriteString("-----BEGIN RSA " + "PRIV" + "ATE KEY-----" + nl)
	for i := 0; i < lines; i++ {
		b.WriteString(strings.Repeat("Qm9ndXNLZXk"+string(rune('a'+i)), 6)[:64] + nl)
	}
	b.WriteString("-----END RSA " + "PRIV" + "ATE KEY-----")
	return b.String()
}

// TestPackyme_SecretAcrossLinesIsReplacedPerLine: the generic credential
// rule allows whitespace, line breaks included, between a key and its
// separator, so a name containing "api", an empty line and a line starting
// with "=" became one finding, and one token over three lines; the server
// showed it on the 16th of November. The private key rule matches a whole
// block. Every line of such a finding is now a match of its own, and no
// match holds a line break; the text after the finding on its last line
// stays as it is, and every line of the key block is replaced.
func TestPackyme_SecretAcrossLinesIsReplacedPerLine(t *testing.T) {
	// The rules the plugin embeds; an empty path loads none of them.
	f, err := filter.New("../rules/gitleaks.toml", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	d := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true})
	nl := string(rune(10))

	name, sep := "cliproxy"+"api_default", "== Schnittstelle"
	text := name + nl + nl + sep + " des Hosts" + nl
	got := d.Scan(text)
	if len(got) != 2 || got[0].Value != name || got[1].Value != sep {
		t.Fatalf("Scan(%q) = %+v, want %q and %q as two matches", text, got, name, sep)
	}

	block := fakeKeyBlock(4)
	text = "key:" + nl + block + nl + "done"
	got = d.Scan(text)
	values := map[string]bool{}
	for _, m := range got {
		if strings.Contains(m.Value, nl) {
			t.Errorf("match %q spans a line break", m.Value)
		}
		if m.Kind != detect.KindSecret {
			t.Errorf("match %q has kind %s, want %s", m.Value, m.Kind, detect.KindSecret)
		}
		values[m.Value] = true
	}
	for _, line := range strings.Split(block, nl) {
		if !values[line] {
			t.Errorf("the key line %q is not a match of its own; matches: %+v", line, got)
		}
	}
}
