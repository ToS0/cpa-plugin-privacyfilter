package detect_test

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"privacyfilter/filter"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

func TestPackyme_UsesEntitiesNotRedacted(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	d := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true})
	if d == nil {
		t.Fatal("NewPackyme returned nil")
	}
	text := "my email is test@example.com and ip 203.0.113.9"
	got := d.Scan(text)
	assertDisjointSorted(t, text, got)
	var email, ip bool
	for _, x := range got {
		switch x.Kind {
		case detect.KindEmail:
			email = x.Value == "test@example.com"
		case detect.KindIPv4:
			ip = x.Value == "203.0.113.9"
		}
		if x.Source != d.Name() {
			t.Fatalf("Source = %q, want %q", x.Source, d.Name())
		}
	}
	if !email || !ip {
		t.Fatalf("Scan = %+v, want the e-mail as KindEmail and the address as KindIPv4 with original text", got)
	}
}

func TestPackyme_IPv6MappedByText(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	d := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true})
	if d == nil {
		t.Fatal("NewPackyme returned nil")
	}
	got := d.Scan("addr 2001:db8:85a3::8a2e:370:7334 end")
	if len(got) == 0 {
		t.Skip("packyme does not report this IPv6 form; nothing to map")
	}
	if got[0].Kind != detect.KindIPv6 {
		t.Fatalf("kind = %q, want KindIPv6 for a colon-separated address", got[0].Kind)
	}
}

// TestPackyme_KindTogglesDropFindings: the library reports addresses and
// e-mail addresses without switches of its own; PackymeConfig applies the
// pattern toggles to its findings, so a switched-off kind is not reported
// by this layer either. Values are assembled at run time so the source
// carries no literal address.
func TestPackyme_KindTogglesDropFindings(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	addr := strings.Join([]string{"100", "73", "67", "152"}, ".")
	mail := "sophie" + "@" + "example.org"
	text := "mail " + mail + " ip " + addr
	on := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true})
	var sawIP, sawMail bool
	for _, x := range on.Scan(text) {
		sawIP = sawIP || x.Kind == detect.KindIPv4
		sawMail = sawMail || x.Kind == detect.KindEmail
	}
	if !sawIP || !sawMail {
		t.Skip("packyme reports neither the address nor the e-mail here; nothing to toggle")
	}
	off := detect.NewPackyme(f, detect.PackymeConfig{IPv4: false, IPv6: true, Email: false})
	for _, x := range off.Scan(text) {
		if x.Kind == detect.KindIPv4 || x.Kind == detect.KindEmail {
			t.Fatalf("Scan with ipv4 and email off still reports %+v", x)
		}
	}
}

// allPackyme switches every finding of the library on, as the defaults do.
var allPackyme = detect.PackymeConfig{IPv4: true, IPv6: true, Email: true, Phone: true, ID: true, BankCard: true}

// luhn appends the check digit that makes prefix pass the Luhn test, so a
// test can build a run the library reports as a bank card without a
// literal number in the source.
func luhn(prefix string) string {
	for d := byte('0'); d <= '9'; d++ {
		s := prefix + string(d)
		sum, double := 0, false
		for i := len(s) - 1; i >= 0; i-- {
			x := int(s[i] - '0')
			if double {
				if x *= 2; x > 9 {
					x -= 9
				}
			}
			sum += x
			double = !double
		}
		if sum%10 == 0 {
			return s
		}
	}
	return ""
}

// assertOnTokenBoundaries fails when a match has a letter or a digit right
// in front of it or right behind it: its pseudonym would continue a word,
// and the return path would never restore it.
func assertOnTokenBoundaries(t *testing.T, text string, got []detect.Match) {
	t.Helper()
	isToken := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
	for _, m := range got {
		if r, _ := utf8.DecodeLastRuneInString(text[:m.Start]); m.Start > 0 && isToken(r) {
			t.Errorf("match %q at %d is glued to the word in front of it in %q", m.Value, m.Start, text)
		}
		if r, _ := utf8.DecodeRuneInString(text[m.End:]); m.End < len(text) && isToken(r) {
			t.Errorf("match %q ending at %d is glued to the word behind it in %q", m.Value, m.End, text)
		}
		if strings.TrimSpace(m.Value) != m.Value {
			t.Errorf("match %q carries edge whitespace", m.Value)
		}
	}
}

// TestPackyme_GluedDigitRunWidensToItsToken: the library bounds a run of
// digits by digits alone, so a Luhn-valid run inside a file name was cut out
// of its word, and its pseudonym came back to the client as it was. The
// layer widens such a span to the whole token and renders it as an opaque
// token; the extension behind the dot stays.
func TestPackyme_GluedDigitRunWidensToItsToken(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	num := luhn("176190000000")
	word := "foto" + num + "x"
	text := "Datei " + word + ".jpg liegt dort, frei " + num + " im Log"
	got := detect.NewPackyme(f, allPackyme).Scan(text)
	assertDisjointSorted(t, text, got)
	assertOnTokenBoundaries(t, text, got)
	var glued, free bool
	for _, m := range got {
		switch m.Value {
		case word:
			glued = m.Kind == detect.KindSecret
		case num:
			free = m.Kind == detect.KindSecret
		}
	}
	if !glued || !free {
		t.Fatalf("Scan = %+v, want %q and the free run %q, both as KindSecret", got, word, num)
	}
}

// TestPackyme_CredentialLeavesTheSpaceBehindIt: a gitleaks rule takes the
// space behind the value as its terminator, so the pseudonym of the whole
// match was glued to the next word. The layer trims the space off.
func TestPackyme_CredentialLeavesTheSpaceBehindIt(t *testing.T) {
	f, err := filter.New("../rules/gitleaks.toml", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	text := "require clear authorization context: pentesting engagements, CTF competitions"
	got := detect.NewPackyme(f, allPackyme).Scan(text)
	if len(got) == 0 {
		t.Skip("the rules report nothing here; nothing to trim")
	}
	assertOnTokenBoundaries(t, text, got)
	for _, m := range got {
		if strings.Contains(m.Value, "engagements") {
			t.Fatalf("match %q swallowed the next word", m.Value)
		}
	}
}

// TestPackyme_DigitTogglesDropFindings: phone, id and bank_card each switch
// off exactly the library rule of that type.
func TestPackyme_DigitTogglesDropFindings(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	values := map[string]string{
		"phone":     "13" + strings.Repeat("0", 9),
		"id":        "1" + strings.Repeat("0", 16) + "X",
		"bank_card": luhn("411111111111111"),
	}
	for name, value := range values {
		text := "Wert " + value + " Ende"
		if got := detect.NewPackyme(f, allPackyme).Scan(text); len(got) != 1 || got[0].Value != value {
			t.Fatalf("%s: Scan with every rule on = %+v, want one match %q", name, got, value)
		}
		cfg := allPackyme
		switch name {
		case "phone":
			cfg.Phone = false
		case "id":
			cfg.ID = false
		case "bank_card":
			cfg.BankCard = false
		}
		if got := detect.NewPackyme(f, cfg).Scan(text); len(got) != 0 {
			t.Fatalf("%s: Scan with the toggle off = %+v, want nothing", name, got)
		}
	}
}

// TestPackyme_EveryMatchStandsOnTokenBoundaries runs the layer over the
// shapes that glued a finding to a word and over ordinary ones.
func TestPackyme_EveryMatchStandsOnTokenBoundaries(t *testing.T) {
	f, err := filter.New("../rules/gitleaks.toml", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	num := luhn("176190000000")
	addr := strings.Join([]string{"100", "73", "67", "152"}, ".")
	texts := []string{
		"IMG" + num + ".jpg",
		"v0.0.0-" + num + "0-7ee5256398cf",
		"id" + num,
		num + "ms",
		"ip" + addr + "x",
		"Müller" + "13" + strings.Repeat("0", 9),
		"token: abcdefghijklmnop\nnext line",
		"api_key = \"abcdefghijklmnop1234\"done",
	}
	for _, text := range texts {
		got := detect.NewPackyme(f, allPackyme).Scan(text)
		assertDisjointSorted(t, text, got)
		assertOnTokenBoundaries(t, text, got)
	}
}
