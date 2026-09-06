package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
)

// errPathNotFound means the requested Path does not exist in the scanned
// bytes. It never leaves the package; callers see it wrapped in the errors
// the exported API documents.
var errPathNotFound = errors.New("payload: path not found in JSON")

// errNotString means the value at the requested Path exists but is not a
// JSON string, so it cannot be replaced as text.
var errNotString = errors.New("payload: value at path is not a JSON string")

// errOverlappingEdits means two replacements in one body overlap, which
// can only come from a broken caller of splice.
var errOverlappingEdits = errors.New("payload: overlapping string edits")

// skipWS returns the index of the first byte at or after i that is not JSON
// whitespace.
func skipWS(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// skipValue returns the index just past the JSON value that begins at i. It
// is a scanner, not a parser: it never allocates and never decodes, it only
// finds the end of the value. Strings are honoured so that braces, brackets
// and quotes inside them do not confuse the nesting count.
func skipValue(b []byte, i int) (int, error) {
	if i >= len(b) {
		return 0, errPathNotFound
	}
	switch b[i] {
	case '"':
		i++
		for i < len(b) {
			switch b[i] {
			case '\\':
				i += 2
			case '"':
				return i + 1, nil
			default:
				i++
			}
		}
		return 0, errPathNotFound
	case '{', '[':
		open := b[i]
		closing := byte('}')
		if open == '[' {
			closing = ']'
		}
		depth := 0
		for i < len(b) {
			switch b[i] {
			case '"':
				j, err := skipValue(b, i)
				if err != nil {
					return 0, err
				}
				i = j
			case open:
				depth++
				i++
			case closing:
				depth--
				i++
				if depth == 0 {
					return i, nil
				}
			default:
				i++
			}
		}
		return 0, errPathNotFound
	default:
		// number, true, false or null: everything up to the next structural
		// byte or whitespace.
		j := i
		for j < len(b) {
			switch b[j] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				if j == i {
					return 0, errPathNotFound
				}
				return j, nil
			}
			j++
		}
		if j == i {
			return 0, errPathNotFound
		}
		return j, nil
	}
}

// findValue returns the byte range [start,end) of the value at path inside
// b, counted from the start of b. Object keys and decimal array indexes are
// followed in the order the path names them. The surrounding bytes are never
// touched, which is what lets SetText splice a replacement into a body
// without disturbing key order or whitespace.
func findValue(b []byte, path Path) (int, int, error) {
	return findFrom(b, 0, path)
}

func findFrom(b []byte, i int, path Path) (int, int, error) {
	i = skipWS(b, i)
	if i >= len(b) {
		return 0, 0, errPathNotFound
	}
	if len(path) == 0 {
		end, err := skipValue(b, i)
		if err != nil {
			return 0, 0, err
		}
		return i, end, nil
	}
	switch b[i] {
	case '{':
		return findInObject(b, i+1, path)
	case '[':
		return findInArray(b, i+1, path)
	}
	return 0, 0, errPathNotFound
}

func findInObject(b []byte, i int, path Path) (int, int, error) {
	for {
		i = skipWS(b, i)
		if i >= len(b) || b[i] == '}' {
			return 0, 0, errPathNotFound
		}
		if b[i] != '"' {
			return 0, 0, errPathNotFound
		}
		keyStart := i
		keyEnd, err := skipValue(b, i)
		if err != nil {
			return 0, 0, err
		}
		var key string
		if err := json.Unmarshal(b[keyStart:keyEnd], &key); err != nil {
			return 0, 0, err
		}
		i = skipWS(b, keyEnd)
		if i >= len(b) || b[i] != ':' {
			return 0, 0, errPathNotFound
		}
		i++
		if key == path[0] {
			return findFrom(b, i, path[1:])
		}
		i, err = skipValue(b, skipWS(b, i))
		if err != nil {
			return 0, 0, err
		}
		i = skipWS(b, i)
		if i < len(b) && b[i] == ',' {
			i++
			continue
		}
		return 0, 0, errPathNotFound
	}
}

func findInArray(b []byte, i int, path Path) (int, int, error) {
	want, err := strconv.Atoi(path[0])
	if err != nil || want < 0 {
		return 0, 0, errPathNotFound
	}
	for n := 0; ; n++ {
		i = skipWS(b, i)
		if i >= len(b) || b[i] == ']' {
			return 0, 0, errPathNotFound
		}
		if n == want {
			return findFrom(b, i, path[1:])
		}
		i, err = skipValue(b, i)
		if err != nil {
			return 0, 0, err
		}
		i = skipWS(b, i)
		if i < len(b) && b[i] == ',' {
			i++
			continue
		}
		return 0, 0, errPathNotFound
	}
}

// encodeString renders s as a JSON string value, quotes included, with the
// escaping encoding/json uses and without HTML escaping, so that <, > and &
// survive as themselves.
func encodeString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		// A Go string always encodes; invalid UTF-8 is replaced, not rejected.
		return []byte(`""`)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// isIndex reports whether an element of a Path is a decimal array index
// rather than an object key. Object keys that consist only of digits are
// indistinguishable here; the Anthropic schema has none.
func isIndex(elem string) bool {
	if elem == "" {
		return false
	}
	for i := 0; i < len(elem); i++ {
		if elem[i] < '0' || elem[i] > '9' {
			return false
		}
	}
	return true
}

// objectType returns the string value of the "type" member of the object
// whose opening brace is at b[i], or "" when there is none. The deny list
// decides by the type of the enclosing objects, and the member may come after
// the string it governs, so the object is looked over once before it is
// walked. b must be valid JSON.
func objectType(b []byte, i int) string {
	i = skipWS(b, i+1)
	for i < len(b) && b[i] != '}' {
		keyStart := i
		keyEnd, err := skipValue(b, i)
		if err != nil {
			return ""
		}
		i = skipWS(b, keyEnd)
		if i >= len(b) || b[i] != ':' {
			return ""
		}
		i = skipWS(b, i+1)
		if i >= len(b) {
			return ""
		}
		valEnd, err := skipValue(b, i)
		if err != nil {
			return ""
		}
		if b[i] == '"' && bytes.Equal(b[keyStart:keyEnd], []byte(`"type"`)) {
			var t string
			if json.Unmarshal(b[i:valEnd], &t) == nil {
				return t
			}
			return ""
		}
		i = skipWS(b, valEnd)
		if i < len(b) && b[i] == ',' {
			i = skipWS(b, i+1)
		}
	}
	return ""
}

// stringScanner walks valid JSON bytes and reports every string value the
// deny list does not cover, with the byte range of its encoded form. It is
// the byte-level counterpart of walker: same paths, same type stack, same
// deny rules, but nothing is decoded or allocated except the object keys.
type stringScanner struct {
	b     []byte
	deny  *DenyList
	path  Path
	types []string
	visit func(path Path, start, end int) error
}

// value walks the value at b[i] and returns the index just past it.
func (s *stringScanner) value(i int) (int, error) {
	switch s.b[i] {
	case '{':
		return s.object(i)
	case '[':
		return s.array(i)
	case '"':
		end, err := skipValue(s.b, i)
		if err != nil {
			return 0, err
		}
		if !s.deny.Denied(s.path, s.types) {
			if err := s.visit(s.path, i, end); err != nil {
				return 0, err
			}
		}
		return end, nil
	default:
		return skipValue(s.b, i)
	}
}

func (s *stringScanner) object(i int) (int, error) {
	s.types = append(s.types, objectType(s.b, i))
	defer func() { s.types = s.types[:len(s.types)-1] }()

	i = skipWS(s.b, i+1)
	for i < len(s.b) && s.b[i] != '}' {
		keyEnd, err := skipValue(s.b, i)
		if err != nil {
			return 0, err
		}
		var key string
		if err := json.Unmarshal(s.b[i:keyEnd], &key); err != nil {
			return 0, err
		}
		i = skipWS(s.b, keyEnd)
		if i >= len(s.b) || s.b[i] != ':' {
			return 0, errPathNotFound
		}
		i = skipWS(s.b, i+1)
		if i >= len(s.b) {
			return 0, errPathNotFound
		}
		s.path = append(s.path, key)
		i, err = s.value(i)
		s.path = s.path[:len(s.path)-1]
		if err != nil {
			return 0, err
		}
		i = skipWS(s.b, i)
		if i < len(s.b) && s.b[i] == ',' {
			i = skipWS(s.b, i+1)
		}
	}
	if i >= len(s.b) {
		return 0, errPathNotFound
	}
	return i + 1, nil
}

func (s *stringScanner) array(i int) (int, error) {
	i = skipWS(s.b, i+1)
	for n := 0; i < len(s.b) && s.b[i] != ']'; n++ {
		s.path = append(s.path, strconv.Itoa(n))
		next, err := s.value(i)
		s.path = s.path[:len(s.path)-1]
		if err != nil {
			return 0, err
		}
		i = skipWS(s.b, next)
		if i < len(s.b) && s.b[i] == ',' {
			i = skipWS(s.b, i+1)
		}
	}
	if i >= len(s.b) {
		return 0, errPathNotFound
	}
	return i + 1, nil
}

// scanStrings calls visit for every string value of the JSON object body
// that deny does not cover, in document order. body must already be valid
// JSON; the scanner does not validate, it only follows the structure. The
// path handed to visit is reused between calls and must be copied to be
// kept.
func scanStrings(body []byte, deny *DenyList, visit func(path Path, start, end int) error) error {
	i := skipWS(body, 0)
	if i >= len(body) || body[i] != '{' {
		return ErrNotJSON
	}
	s := &stringScanner{b: body, deny: deny, visit: visit}
	_, err := s.value(i)
	return err
}

// stringEdit is one replacement of an encoded string value in a body.
type stringEdit struct {
	start, end int
	enc        []byte
}

// splice writes body with every edit applied. edits must be in document
// order and disjoint; an overlap is reported as an error rather than a
// panic, because a broken caller must not fuse the plugin.
func splice(body []byte, edits []stringEdit) ([]byte, error) {
	size := len(body)
	prev := 0
	for _, e := range edits {
		if e.start < prev || e.end < e.start || e.end > len(body) {
			return nil, errOverlappingEdits
		}
		size += len(e.enc) - (e.end - e.start)
		prev = e.end
	}
	out := make([]byte, 0, size)
	prev = 0
	for _, e := range edits {
		out = append(out, body[prev:e.start]...)
		out = append(out, e.enc...)
		prev = e.end
	}
	return append(out, body[prev:]...), nil
}

// decodeString returns the Go string for the encoded JSON string raw, quotes
// included. A string without escapes is the bytes between the quotes and
// costs no decoding.
func decodeString(raw []byte) (string, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", errNotString
	}
	if bytes.IndexByte(raw, '\\') < 0 {
		return string(raw[1 : len(raw)-1]), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errNotString
	}
	return s, nil
}
