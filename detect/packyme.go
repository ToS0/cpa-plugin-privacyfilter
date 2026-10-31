package detect

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"privacyfilter/filter"
)

// PackymeConfig says which of the library's own findings are kept. The
// library has no switches per kind: it always reports IP addresses and
// e-mail addresses next to the credential rules. The toggles of the
// structural patterns are therefore applied to its findings here, so that
// switching ipv4 off means no IPv4 address is replaced by any layer.
//
// Phone, ID and BankCard keep the library's three digit rules, named after
// the type ids it reports: a mainland Chinese mobile number (eleven digits
// from 13 on), an 18-digit identity number, and any run of 13 to 19 digits
// that passes the Luhn check, which is one in ten of them, millisecond
// timestamps and pseudo-version dates included. Each is rendered as an
// opaque token like a credential. The credential rules themselves are
// always kept; they are switched off as a whole with the layer.
type PackymeConfig struct {
	IPv4     bool
	IPv6     bool
	Email    bool
	Phone    bool
	ID       bool
	BankCard bool
}

// NewPackyme wraps the existing detection library as one layer. It calls
// Redact and uses only the Entities of the result: Start and End become the
// span, Text becomes Value, and Type is translated with KindFromPackyme. The
// field Redacted is ignored. Findings of a kind or type that cfg switches
// off are dropped, and every other span is fitted to whole tokens, see
// fitToTokens.
//
// The wrapped filter must be the same instance the redact mode uses, so both
// modes see identical hits.
func NewPackyme(f *filter.Filter, cfg PackymeConfig) Detector {
	return &packymeDetector{filter: f, cfg: cfg}
}

// packymeDetector adapts packyme/privacy-filter to the Detector interface.
type packymeDetector struct {
	filter *filter.Filter
	cfg    PackymeConfig
}

var _ Detector = (*packymeDetector)(nil)

// Name implements Detector.
func (p *packymeDetector) Name() string { return "packyme" }

// Scan implements Detector. Redact is called for its Entities alone; the
// redacted text it also produces belongs to the other mode and is dropped
// here. Value is taken from the scanned text rather than from Entity.Text so
// the span and the value can never disagree.
func (p *packymeDetector) Scan(text string) []Match {
	if p == nil || p.filter == nil || text == "" {
		return nil
	}
	res := p.filter.Redact(text)
	if len(res.Entities) == 0 {
		return nil
	}
	hits := make([]Match, 0, len(res.Entities))
	for _, e := range res.Entities {
		if !spanAligned(text, e.Start, e.End) || !p.keepsType(e.Type) {
			continue
		}
		kind := KindFromPackyme(e.Type)
		// The library files both address families under one type; the text
		// decides which one it is.
		if kind == KindIPv4 && strings.Contains(text[e.Start:e.End], ":") {
			kind = KindIPv6
		}
		if !p.keeps(kind) {
			continue
		}
		start, end, widened, ok := fitToTokens(text, e.Start, e.End)
		if !ok {
			continue
		}
		if widened {
			// The span now holds letters or digits around the finding, so
			// it is no longer an address or an e-mail address, and only
			// the opaque token renders it.
			kind = KindSecret
		}
		hits = append(hits, Match{Start: start, End: end, Value: text[start:end], Kind: kind, Source: "packyme"})
	}
	return Merge(hits)
}

// keeps applies the kind toggles of PackymeConfig. Every kind the config
// does not name is kept.
func (p *packymeDetector) keeps(kind Kind) bool {
	switch kind {
	case KindIPv4:
		return p.cfg.IPv4
	case KindIPv6:
		return p.cfg.IPv6
	case KindEmail:
		return p.cfg.Email
	}
	return true
}

// keepsType applies the toggles of the digit rules, which the library
// reports under types of their own but which all map to KindSecret.
func (p *packymeDetector) keepsType(entityType string) bool {
	switch entityType {
	case PackymeTypePhone:
		return p.cfg.Phone
	case PackymeTypeIdentity:
		return p.cfg.ID
	case PackymeTypeBankCard:
		return p.cfg.BankCard
	}
	return true
}

// fitToTokens trims the edge whitespace off a span the library reported and
// widens what is left until no letter or digit touches it, and reports
// whether it widened and whether anything is left. Every pseudonym of this
// layer begins and ends with a letter or a digit, and the return path
// restores a pseudonym only where neither side continues a word, see
// mapping.Restorer: a span cut out of a word would leave the model a token
// that never comes back. The library bounds its digit rules by digits
// alone, so a Luhn-valid run inside a file name is cut out of its word, and
// a gitleaks rule takes the space behind the value as its terminator, so
// the pseudonym is glued to the next word. The rule on both sides is the one
// of hasTokenBoundaries, with a percent-escape in front delimiting as well.
func fitToTokens(text string, start, end int) (int, int, bool, bool) {
	for start < end {
		r, size := utf8.DecodeRuneInString(text[start:end])
		if !unicode.IsSpace(r) {
			break
		}
		start += size
	}
	for end > start {
		r, size := utf8.DecodeLastRuneInString(text[start:end])
		if !unicode.IsSpace(r) {
			break
		}
		end -= size
	}
	if start >= end {
		return start, end, false, false
	}
	widened := false
	for start > 0 && !PercentEscapeEnds(text[:start]) {
		r, size := utf8.DecodeLastRuneInString(text[:start])
		if !isTokenRune(r) {
			break
		}
		start -= size
		widened = true
	}
	for end < len(text) {
		r, size := utf8.DecodeRuneInString(text[end:])
		if !isTokenRune(r) {
			break
		}
		end += size
		widened = true
	}
	return start, end, widened, true
}

// Type ids the library writes into Entity.Type (filter/pii.go and
// filter/secrets.go). They are the keys of replacement_labels as well. Every
// credential rule reports PackymeTypeSecret, whatever its rule id; the label
// a type is rendered with in redact mode is not part of Entity.Type.
const (
	PackymeTypeEmail    = "email"
	PackymeTypePhone    = "phone"
	PackymeTypeIdentity = "id"
	PackymeTypeIP       = "ip"
	PackymeTypeBankCard = "bank_card"
	PackymeTypeSecret   = "secret"
)

// KindFromPackyme maps an Entity.Type of the library to a Kind.
// PackymeTypeEmail maps to KindEmail. PackymeTypeIP covers both address
// families in the library; the wrapper decides between KindIPv4 and KindIPv6
// by parsing Entity.Text, which is why the type alone maps to KindIPv4 here
// and the wrapper corrects it for colon-separated addresses. Every other
// type, including phone numbers, identity numbers, bank cards, the credential
// rules and any type a later library adds, maps to KindSecret and is rendered
// as an opaque token.
func KindFromPackyme(entityType string) Kind {
	switch entityType {
	case PackymeTypeEmail:
		return KindEmail
	case PackymeTypeIP:
		return KindIPv4
	}
	return KindSecret
}
