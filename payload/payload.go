// Package payload knows the shape of the request and response bodies: which
// strings of a request may be rewritten, which must be left alone, and where
// the text lives in an Anthropic stream event.
//
// The forward pass walks every string in the JSON body and skips only what
// the deny list names. The original plugin did the opposite and filtered two
// fields; everything else, including the system prompt, tool results and
// tool arguments, went out untouched. The deny list exists for fields whose
// change would break the request (ids, signatures, base64 data) or that
// carry no secret (role, type, model).
package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// defaultMaxBodyBytes is the body limit of the plan, used when
// WalkOptions.MaxBodyBytes is zero.
const defaultMaxBodyBytes = 32 << 20

// ErrNotImplemented marks a contract stub that has no implementation yet.
var ErrNotImplemented = errors.New("payload: not implemented")

// ErrBodyTooLarge is returned by Walk when the body exceeds the configured
// limit. In block mode the request is then terminated.
var ErrBodyTooLarge = errors.New("payload: body exceeds size limit")

// ErrNotJSON is returned by Walk when the body does not parse as a JSON
// object. In block mode the request is then terminated.
var ErrNotJSON = errors.New("payload: body is not a JSON object")

// Path locates a string inside the JSON tree. Elements are object keys or
// decimal array indexes, so messages[2].content[0].text is
// Path{"messages", "2", "content", "0", "text"}. Paths are used by the deny
// list and reported to the Visitor.
type Path []string

// String renders the path in dotted form with bracketed indexes, as in the
// example above, for logs and tests.
func (p Path) String() string {
	var b strings.Builder
	for i, elem := range p {
		switch {
		case i == 0:
			b.WriteString(elem)
		case isIndex(elem):
			b.WriteByte('[')
			b.WriteString(elem)
			b.WriteByte(']')
		default:
			b.WriteByte('.')
			b.WriteString(elem)
		}
	}
	return b.String()
}

// Visitor is called for every string value that is not denied. It returns
// the replacement and whether the string changed. Returning changed == false
// leaves the original bytes in place; the body is then re-serialized only if
// at least one visitor call changed something.
type Visitor func(path Path, value string) (out string, changed bool)

// WalkOptions bounds one walk.
type WalkOptions struct {
	// MaxBodyBytes rejects larger bodies with ErrBodyTooLarge. Zero means
	// 32 MiB, the default of the plan.
	MaxBodyBytes int
	// Deny is the deny list to apply; nil means DefaultDeny.
	Deny *DenyList
}

// Walk parses body as a JSON object, calls visit for every string value
// whose path the deny list does not cover, and returns the re-serialized
// body. When no visitor call reports a change, Walk returns body itself
// (same backing array) and changed == false, so redact mode can keep its
// current "nil means unchanged" behaviour and no bytes move.
//
// Serialization must be stable: encoding/json's sorted object keys, no HTML
// escaping, no trailing newline. Number values are preserved as written
// (json.Number), so 1.0 does not become 1 and large integers keep their
// digits. Strings are re-encoded, which normalizes escape sequences; that is
// acceptable because the upstream parses the body again.
func Walk(body []byte, opts WalkOptions, visit Visitor) (out []byte, changed bool, err error) {
	limit := opts.MaxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}
	if len(body) > limit {
		return nil, false, ErrBodyTooLarge
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, false, ErrNotJSON
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, false, ErrNotJSON
	}

	deny := opts.Deny
	if deny == nil {
		deny = DefaultDeny()
	}
	w := walker{deny: deny, visit: visit}
	w.node(obj)
	if !w.changed {
		// Same backing array, so redact mode can keep treating an unchanged
		// body as "nothing to do" without comparing bytes.
		return body, false, nil
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, false, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), true, nil
}

// walker carries the state of one Walk: the current path, the "type" values
// of the enclosing objects and whether any visitor reported a change.
type walker struct {
	deny    *DenyList
	visit   Visitor
	path    Path
	types   []string
	changed bool
}

// node rewrites v in place and returns the value that belongs at its
// position. Object keys are visited in sorted order so that the sequence of
// visitor calls does not depend on Go's map iteration order.
func (w *walker) node(v any) any {
	switch x := v.(type) {
	case map[string]any:
		// An object without a "type" key contributes an empty entry, so the
		// depth of the type stack always matches the depth of the object
		// nesting. Denied needs that to tell tool_use.name, which is a tool
		// name, from tool_use.input.name, which is an argument.
		blockType, _ := x["type"].(string)
		w.types = append(w.types, blockType)
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.path = append(w.path, k)
			x[k] = w.node(x[k])
			w.path = w.path[:len(w.path)-1]
		}
		w.types = w.types[:len(w.types)-1]
		return x
	case []any:
		for i := range x {
			w.path = append(w.path, strconv.Itoa(i))
			x[i] = w.node(x[i])
			w.path = w.path[:len(w.path)-1]
		}
		return x
	case string:
		if w.visit == nil || w.deny.Denied(w.path, w.types) {
			return x
		}
		out, changed := w.visit(w.path, x)
		if !changed {
			return x
		}
		w.changed = true
		return out
	default:
		// Numbers stay json.Number, booleans and null stay as parsed.
		return v
	}
}
