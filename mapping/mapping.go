// Package mapping holds the pseudonym-to-original tables that the forward
// pass builds and the return pass consumes. One Table belongs to one
// conversation: every request of the conversation adds the values it
// carries and reads the whole table on its way back, so a pseudonym the
// model repeats from an earlier turn still resolves. The Store keeps the
// tables by session and binds every request to its session under the host's
// RequestID; the same RequestID arrives with the request interceptor, the
// stream header call, every chunk and the completion event, so it is the
// only key the return path needs.
//
// Tables hold clear-text values for as long as the conversation is in use.
// A table that has not been touched for the TTL is dropped; a request's
// binding is removed on the request.complete lifecycle event.
package mapping

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// ErrNotImplemented marks a contract stub that has no implementation yet.
var ErrNotImplemented = errors.New("mapping: not implemented")

// ErrTableNotFound is returned by Store.Get for an unknown RequestID or one
// whose session table has expired. The return pass then passes the response
// through unchanged and logs the incident.
var ErrTableNotFound = errors.New("mapping: no table for request")

// Generator is the part of pseudo.Generator the table needs. It is an
// interface here so the table can be tested with a fake.
type Generator interface {
	Pseudonym(kind detect.Kind, value string, attempt int) string
}

// Entry is one row of a Table.
type Entry struct {
	Kind      detect.Kind
	Original  string
	Pseudonym string
	// Attempt is the collision counter that produced Pseudonym; 0 in the
	// common case.
	Attempt int
}

// maxGeneratorAttempts bounds the collision loop. A generator that ignores
// its attempt argument would otherwise spin forever under the table lock;
// past the bound the table disambiguates on its own, deterministically. With
// the real generator the bound is never reached.
const maxGeneratorAttempts = 1024

// tableKey is the identity of an entry: kind and original value together.
type tableKey struct {
	kind  detect.Kind
	value string
}

// Table maps originals to pseudonyms and back for one conversation. It is
// filled on every forward pass of the conversation and read on every return
// pass; a Table is safe for concurrent use because a stream chunk of one
// request may be restored while the next request of the same conversation
// is being scanned.
type Table struct {
	mu          sync.RWMutex
	gen         Generator
	byKey       map[tableKey]Entry
	byPseudonym map[string]Entry
	// originals counts the rows per original value, so a pseudonym that
	// would equal a value the table already holds as an original is never
	// handed out: the text would then carry the same token in two
	// meanings, and the forward pass of the next request would exclude the
	// real value as its own output.
	originals map[string]int
	// avoid, when set, names further values a pseudonym must not equal; the
	// plugin passes the literals of its term list. See SetAvoid.
	avoid  func(pseudonym string) bool
	maxLen int
	// version counts the inserts. The restorer's search trie carries the
	// version it was built from and is rebuilt when the two differ, so a
	// row added by a later request is found by the next restore without
	// anybody freezing the table.
	version atomic.Uint64

	// session is the key the Store filed the table under; empty for a
	// table built outside a store.
	session string

	// trie is the current search structure, nil until the first restore.
	// trieMu serialises the rebuild; readers take the pointer without it.
	trieMu sync.Mutex
	trie   atomic.Pointer[trie]

	// hits counts the swaps per pseudonym over the whole life of the table.
	// The store keeps a snapshot per request and reports the difference at
	// completion.
	hitsMu sync.Mutex
	hits   map[string]int

	// restorer is the one live handle over the table; see Restorer.
	restorer restorer
}

// NewTable creates an empty table bound to a generator.
func NewTable(gen Generator) *Table {
	t := &Table{
		gen:         gen,
		byKey:       make(map[tableKey]Entry),
		byPseudonym: make(map[string]Entry),
		originals:   make(map[string]int),
	}
	t.restorer.t = t
	return t
}

// setGenerator replaces the generator for the rows added from now on. The
// store calls it on every request, so a configuration reload that changes
// the renderers or the networks reaches a conversation that is already
// running; the rows that exist keep their pseudonyms.
func (t *Table) setGenerator(gen Generator) {
	if gen == nil {
		return
	}
	t.mu.Lock()
	t.gen = gen
	t.mu.Unlock()
}

// SetAvoid names values a pseudonym must never equal, beyond the originals
// the table holds. The plugin passes a test over the literals of its term
// list: a term that lies in the range a kind draws its pseudonyms from,
// such as a node address out of the carrier-grade NAT range, must not be
// handed out as the pseudonym of another value, or the forward pass would
// take the real value for the plugin's own output and leave it in the
// clear. The generator raises the attempt past such a value like past a
// collision. A nil test clears the rule.
func (t *Table) SetAvoid(avoid func(pseudonym string) bool) {
	t.mu.Lock()
	t.avoid = avoid
	t.mu.Unlock()
}

// Lookup returns the pseudonym for value under kind, creating the entry on
// first use. The pair (kind, value) is the identity of an entry: the same
// pair always returns the same pseudonym within a table, and because the
// generator is deterministic, the same pseudonym across the whole
// conversation as long as no collision occurred.
//
// Collisions are resolved on insert: if the pseudonym for attempt 0 is
// already taken by a different (kind, value), attempt is raised until a free
// pseudonym is found. The chosen attempt is recorded in the Entry. A
// collision raises the attempt only for the later of the two values, so the
// first value keeps the pseudonym the conversation already knows.
func (t *Table) Lookup(kind detect.Kind, value string) string {
	key := tableKey{kind: kind, value: value}

	t.mu.RLock()
	e, ok := t.byKey[key]
	t.mu.RUnlock()
	if ok {
		return e.Pseudonym
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// Another goroutine may have inserted the entry between the two locks.
	if e, ok := t.byKey[key]; ok {
		return e.Pseudonym
	}

	attempt := 0
	var pseudonym string
	for {
		pseudonym = t.render(kind, value, attempt)
		_, taken := t.byPseudonym[pseudonym]
		if !taken && t.originals[pseudonym] == 0 && pseudonym != value && (t.avoid == nil || !t.avoid(pseudonym)) {
			break
		}
		attempt++
	}

	e = Entry{Kind: kind, Original: value, Pseudonym: pseudonym, Attempt: attempt}
	t.byKey[key] = e
	t.byPseudonym[pseudonym] = e
	t.originals[value]++
	if len(pseudonym) > t.maxLen {
		t.maxLen = len(pseudonym)
	}
	t.version.Add(1)
	return pseudonym
}

// render asks the generator for the pseudonym of one attempt. Beyond
// maxGeneratorAttempts it appends the attempt itself, so the collision loop
// terminates even against a generator that ignores the argument.
func (t *Table) render(kind detect.Kind, value string, attempt int) string {
	if attempt < maxGeneratorAttempts {
		return t.gen.Pseudonym(kind, value, attempt)
	}
	return t.gen.Pseudonym(kind, value, maxGeneratorAttempts-1) + "#" + strconv.Itoa(attempt)
}

// Original returns the original for a pseudonym and whether it exists.
func (t *Table) Original(pseudonym string) (Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byPseudonym[pseudonym]
	return e, ok
}

// Knows reports whether value is a pseudonym of this table, in the spelling
// the table wrote or, for the hex-token kinds, in upper case. The composite
// of the forward pass uses it as its exclude: a value the table produced is
// not detected and replaced a second time, and a real value that merely has
// the shape of a pseudonym, such as a node address out of the carrier-grade
// NAT range, is replaced like any other.
func (t *Table) Knows(value string) bool {
	if value == "" {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if _, ok := t.byPseudonym[value]; ok {
		return true
	}
	if lower := strings.ToLower(value); lower != value {
		if e, ok := t.byPseudonym[lower]; ok && upperCaseRestores(e.Kind) {
			return true
		}
	}
	return false
}

// Entries returns all rows sorted by Pseudonym, for tests and diagnostics.
// The slice is a copy.
func (t *Table) Entries() []Entry {
	t.mu.RLock()
	out := make([]Entry, 0, len(t.byPseudonym))
	for _, e := range t.byPseudonym {
		out = append(out, e)
	}
	t.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Pseudonym < out[j].Pseudonym })
	return out
}

// Len returns the number of rows.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byKey)
}

// Pseudonyms returns every pseudonym in the table, sorted by descending
// length and then lexically. The return pass replaces in this order so a
// pseudonym that is a prefix of another (not possible with the default
// renderers, but not ruled out by the interface) is never matched too early.
func (t *Table) Pseudonyms() []string {
	t.mu.RLock()
	out := make([]string, 0, len(t.byPseudonym))
	for p := range t.byPseudonym {
		out = append(out, p)
	}
	t.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// MaxPseudonymLen returns the length in bytes of the longest pseudonym in
// the table, 0 for an empty table. The stream holdback is bounded by it.
func (t *Table) MaxPseudonymLen() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.maxLen
}

// Restorer returns the live restorer over the table. It is one handle for
// the life of the table: every response and every stream chunk of every
// request of the conversation shares it, and a row added by a later request
// is found by the next call, because the search trie is rebuilt from the
// rows whenever the table has grown since it was built. Building it per
// change costs one pass over the rows, which happens once per request in
// the ordinary case; building it per chunk would cost more than the
// restoring.
func (t *Table) Restorer() Restorer {
	return &t.restorer
}

// RestoredHits returns how often each pseudonym of the table was swapped
// back so far, keyed by pseudonym, or nil when nothing was ever restored.
// The map is a copy. The store diffs two snapshots of it to report the
// swaps of one request.
func (t *Table) RestoredHits() map[string]int {
	t.hitsMu.Lock()
	defer t.hitsMu.Unlock()
	if len(t.hits) == 0 {
		return nil
	}
	out := make(map[string]int, len(t.hits))
	for k, v := range t.hits {
		out[k] = v
	}
	return out
}

func (t *Table) countHit(pseudonym string) {
	t.hitsMu.Lock()
	if t.hits == nil {
		t.hits = make(map[string]int)
	}
	t.hits[pseudonym]++
	t.hitsMu.Unlock()
}

// currentTrie returns the search trie for the rows as they are now. The
// fast path is two atomic loads; the trie is rebuilt under trieMu only when
// a row was added since the last build.
func (t *Table) currentTrie() *trie {
	if tr := t.trie.Load(); tr != nil && tr.version == t.version.Load() {
		return tr
	}
	t.trieMu.Lock()
	defer t.trieMu.Unlock()
	if tr := t.trie.Load(); tr != nil && tr.version == t.version.Load() {
		return tr
	}
	t.mu.RLock()
	tr := &trie{root: &trieNode{}, version: t.version.Load()}
	for _, e := range t.byPseudonym {
		if e.Pseudonym == "" {
			// An empty pseudonym would match everywhere and replace nothing.
			continue
		}
		tr.insert(e)
		if len(e.Pseudonym) > tr.maxLen {
			tr.maxLen = len(e.Pseudonym)
		}
	}
	t.mu.RUnlock()
	t.trie.Store(tr)
	return tr
}

// Restorer replaces pseudonyms in a text with their originals. It is one
// handle per table, shared by all requests of the conversation and all
// chunks of their streams.
type Restorer interface {
	// Restore returns text with every pseudonym of the table replaced by its
	// original. escaped selects the JSON-escaped form of the originals, for
	// use inside partial_json fragments where the text is still in JSON
	// string encoding; pseudonyms are ASCII without escapable characters and
	// read the same in both forms. When nothing matches, Restore returns text
	// unchanged and changed == false.
	//
	// A pseudonym is only replaced where it stands on its own: an occurrence
	// that continues a token on either side is left untouched. Person
	// pseudonyms are ordinary words, so without that rule a pseudonym such as
	// "Ruth" would rewrite the middle of "Ruthless" in the model's answer,
	// and an address pseudonym would rewrite the front of a longer address.
	// The rule is the one of the structural detectors: letters and digits
	// continue a token, everything else delimits, the underscore included.
	// That is looser than the term list's rule, and deliberately so: a
	// pseudonym the forward pass inserted next to an underscore, as in
	// "scan_<address>.log", must come back, and restoring one the model
	// wrote there itself only shows the user a value that is their own.
	Restore(text string, escaped bool) (out string, changed bool)
	// Holdback returns the length in bytes of the tail of text that has to
	// wait for the next fragment because it may still grow into a pseudonym:
	// everything from the first position where the walk over the table's
	// pseudonyms reaches the end of text undecided. A pseudonym that is
	// complete before that position is never part of the tail, so the tail
	// never cuts into one; the case the rule exists for is a complete
	// pseudonym whose last byte happens to begin another pseudonym. The
	// stream restores what lies in front of the tail with Restore and gets
	// the same matches, because both walk the text the same way. The result
	// is 0 when nothing is pending, never splits a UTF-8 sequence and is at
	// most MaxPseudonymLen()-1.
	Holdback(text string) int
	// Hits returns how often Restore swapped each pseudonym back so far,
	// keyed by pseudonym. The map is a copy; the counting is safe for the
	// concurrent use the stream makes of one restorer.
	Hits() map[string]int
}

// NewRestorer returns the restorer over t, the same handle Table.Restorer
// returns; it is kept for callers that hold a table without a store. A nil
// table gives a restorer that restores nothing.
func NewRestorer(t *Table) Restorer {
	if t == nil {
		return &restorer{}
	}
	return t.Restorer()
}

// trieNode is one byte of a pseudonym in the restorer's search trie. The
// trie gives a single left-to-right pass over the text: at every position at
// most one walk down the trie happens, and the walk is bounded by the longest
// pseudonym, so Restore is linear in the length of the text for the table
// sizes this plugin sees.
type trieNode struct {
	children map[byte]*trieNode
	// terminal is set on the last byte of a pseudonym.
	terminal bool
	// plain and escaped are the original in both forms, valid when terminal;
	// pseudonym is the key of the row, for the hit count.
	plain     string
	escaped   string
	pseudonym string
}

// trie is one build of the search structure over the rows of a table. It is
// immutable once built; a table that grows gets a new one.
type trie struct {
	root *trieNode
	// starts marks every byte that begins some pseudonym, so the scan skips
	// over uninteresting stretches without touching the trie.
	starts [256]bool
	maxLen int
	// version is the table version the rows were read at.
	version uint64
}

// restorer is the live handle over a table. A zero restorer, with t nil,
// restores nothing and holds nothing back.
type restorer struct {
	t *Table
}

// Hits implements Restorer.
func (r *restorer) Hits() map[string]int {
	if r.t == nil {
		return map[string]int{}
	}
	hits := r.t.RestoredHits()
	if hits == nil {
		return map[string]int{}
	}
	return hits
}

// current returns the trie to scan with, or nil when there is nothing to
// find.
func (r *restorer) current() *trie {
	if r.t == nil {
		return nil
	}
	tr := r.t.currentTrie()
	if tr.maxLen == 0 {
		return nil
	}
	return tr
}

// insert adds a row and its alias spellings to the trie.
func (tr *trie) insert(e Entry) {
	tr.insertSpelling(e, e.Pseudonym, false)
	if upper := strings.ToUpper(e.Pseudonym); upper != e.Pseudonym && upperCaseRestores(e.Kind) {
		// A model writes a token in upper case in a heading or a constant
		// ("H-E2BA…", "02:E8:F5:…"); it means the same thing and comes
		// back as the same original. Person pseudonyms are excluded: their
		// case variants are distinct rows of the table.
		tr.insertSpelling(e, upper, true)
	}
	if bare, ok := withoutReservedSuffix(e); ok {
		// A model reads the reserved ".invalid" of a domain or e-mail
		// pseudonym as the marker it is and writes the name without it:
		// "d-e2ba…" for "d-e2ba….invalid", "u-…@d-…" for the address. The
		// bare spelling means the same domain and comes back as the same
		// original; a suffix glued to it ("d-e2ba….bak") restores like any
		// other glued suffix. The full spelling is longer and wins where it
		// is present, so ".invalid" is never left behind.
		tr.insertSpelling(e, bare, true)
		if upper := strings.ToUpper(bare); upper != bare {
			tr.insertSpelling(e, upper, true)
		}
	}
}

// reservedSuffix is the top-level domain of domain and e-mail pseudonyms,
// see pseudo.SuffixDomain. It is spelled here rather than imported so that
// mapping keeps depending on detect only.
const reservedSuffix = ".invalid"

// withoutReservedSuffix returns the pseudonym of a domain or e-mail row
// without its ".invalid" and true, or "" and false for every other row.
func withoutReservedSuffix(e Entry) (string, bool) {
	if e.Kind != detect.KindDomain && e.Kind != detect.KindEmail {
		return "", false
	}
	bare := strings.TrimSuffix(e.Pseudonym, reservedSuffix)
	if bare == e.Pseudonym || bare == "" || strings.HasSuffix(bare, "@") {
		return "", false
	}
	return bare, true
}

// upperCaseRestores reports whether the pseudonyms of kind are restored in
// upper case as well. It covers the kinds whose pseudonyms are hex tokens
// or hex addresses; a person pseudonym carries its own case.
func upperCaseRestores(kind detect.Kind) bool {
	switch kind {
	case detect.KindHost, detect.KindDomain, detect.KindEmail, detect.KindPathSegment, detect.KindFileName,
		detect.KindSecret, detect.KindUUID, detect.KindHexID, detect.KindMAC, detect.KindIPv6, detect.KindCIDR:
		return true
	}
	return false
}

// insertSpelling adds one spelling of e.Pseudonym to the trie; the row's
// original and pseudonym are the same for every spelling. An alias (upper
// case, bare domain) never displaces a spelling that is already there: the
// pseudonyms of a table are distinct, so an occupied node belongs either to
// another row's own pseudonym, which keeps precedence, or to an equal alias
// of the same row.
func (tr *trie) insertSpelling(e Entry, spelling string, alias bool) {
	node := tr.root
	for i := 0; i < len(spelling); i++ {
		b := spelling[i]
		if node.children == nil {
			node.children = make(map[byte]*trieNode, 4)
		}
		next, ok := node.children[b]
		if !ok {
			next = &trieNode{}
			node.children[b] = next
		}
		node = next
	}
	if alias && node.terminal {
		return
	}
	node.terminal = true
	node.plain = e.Original
	node.escaped = jsonEscape(e.Original)
	node.pseudonym = e.Pseudonym
	tr.starts[spelling[0]] = true
}

// Restore implements Restorer. It walks the text once and replaces the
// longest pseudonym that starts at each position, so a pseudonym that is a
// prefix of another never wins over the longer one. Text inserted for an
// original is never rescanned. A hit that is not delimited on both sides is
// skipped; see the Restorer interface for why.
func (r *restorer) Restore(text string, escaped bool) (string, bool) {
	tr := r.current()
	if tr == nil || text == "" {
		return text, false
	}

	var b strings.Builder
	changed := false
	last := 0

	for i := 0; i < len(text); {
		if !tr.starts[text[i]] {
			i++
			continue
		}
		hit, end := tr.longestAt(text, i)
		if hit == nil || !delimited(text, i, end) {
			i++
			continue
		}
		if !changed {
			b.Grow(len(text) + len(text)/8)
			changed = true
		}
		b.WriteString(text[last:i])
		if escaped {
			b.WriteString(hit.escaped)
		} else {
			b.WriteString(hit.plain)
		}
		r.t.countHit(hit.pseudonym)
		i = end
		last = end
	}

	if !changed {
		return text, false
	}
	b.WriteString(text[last:])
	return b.String(), true
}

// longestAt returns the terminal node of the longest pseudonym starting at
// text[i] and the byte offset just behind it, or nil when none starts there.
func (tr *trie) longestAt(text string, i int) (*trieNode, int) {
	node := tr.root
	var hit *trieNode
	end := 0
	for j := i; j < len(text); j++ {
		next, ok := node.children[text[j]]
		if !ok {
			break
		}
		node = next
		if node.terminal {
			hit, end = node, j+1
		}
	}
	return hit, end
}

// isTokenRune reports whether r continues a token for the boundary rule:
// letters and digits, as in the structural detectors. Dot, hyphen and the
// underscore count as separators, so an address or domain pseudonym is
// still found next to them; see the Restorer interface for why the
// underscore is not a word character here.
func isTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// delimited reports whether the match text[start:end] stands on its own. Only
// the sides that actually carry a token rune are checked: a pseudonym that
// begins or ends with punctuation may sit directly against a letter without
// growing a word, which keeps matches inside JSON and inside paths working.
//
// The edges of text count as delimiters. On the stream that is not the whole
// truth — the neighbouring rune may live in the previous or the next chunk —
// but Holdback keeps a pseudonym that could still grow whole until the next
// fragment, and one that is complete and cannot grow is restored at the edge.
// The residual case is a pseudonym split from its neighbouring word by
// exactly the chunk boundary; it is accepted, and it is the behaviour that was
// in place before the boundary rule anyway.
func delimited(text string, start, end int) bool {
	if start > 0 {
		if first, _ := utf8.DecodeRuneInString(text[start:end]); isTokenRune(first) {
			if prev, _ := utf8.DecodeLastRuneInString(text[:start]); isTokenRune(prev) {
				return false
			}
		}
	}
	if end < len(text) {
		if last, _ := utf8.DecodeLastRuneInString(text[start:end]); isTokenRune(last) {
			if next, _ := utf8.DecodeRuneInString(text[end:]); isTokenRune(next) {
				return false
			}
		}
	}
	return true
}

// Holdback implements Restorer. It is the scan of Restore without the
// output: at every position that begins a pseudonym the trie is walked as
// far as the text goes. A walk that ends inside the text is decided, and
// the scan goes on behind the match, or one byte further when there is
// none or it is not delimited. A walk that consumes the text to its end
// while the trie could go on is undecided, and everything from its start
// is held back, a complete shorter match inside it included: the next
// fragment may turn it into a longer pseudonym, and the scan of the joined
// text decides. A held tail is shorter than the pseudonym it could become,
// and it begins at a pseudonym's first byte, which is ASCII, so it never
// splits a rune.
//
// Before this scan the holdback was the longest suffix that is a proper
// prefix of some pseudonym, which cut a complete pseudonym in two whenever
// its last byte could begin another one: "d-…d" followed by a fragment
// boundary lost its last byte to the holdback, and neither piece was ever
// restored. Path segment pseudonyms end in a hex digit and begin with "d",
// so one in sixteen of them was at risk at every fragment boundary.
func (r *restorer) Holdback(text string) int {
	tr := r.current()
	if tr == nil {
		return 0
	}
	for i := 0; i < len(text); {
		if !tr.starts[text[i]] {
			i++
			continue
		}
		if i > 0 {
			// A pseudonym that would continue the word in front of it is
			// never restored, so it is not worth waiting for either.
			prev, _ := utf8.DecodeLastRuneInString(text[:i])
			first, _ := utf8.DecodeRuneInString(text[i:])
			if isTokenRune(prev) && isTokenRune(first) {
				i++
				continue
			}
		}
		node := tr.root
		var hit *trieNode
		end := 0
		j := i
		for ; j < len(text); j++ {
			next, ok := node.children[text[j]]
			if !ok {
				break
			}
			node = next
			if node.terminal {
				hit, end = node, j+1
			}
		}
		if j == len(text) && len(node.children) > 0 {
			return len(text) - i
		}
		if hit != nil && delimited(text, i, end) {
			i = end
			continue
		}
		i++
	}
	return 0
}

// jsonEscape returns s in the form encoding/json writes it into a string,
// without HTML escaping and without the surrounding quotes.
func jsonEscape(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		// json.Encoder only fails on unsupported types; a string is never one.
		return s
	}
	out := strings.TrimRight(buf.String(), "\n")
	if len(out) >= 2 && out[0] == '"' && out[len(out)-1] == '"' {
		return out[1 : len(out)-1]
	}
	return out
}
