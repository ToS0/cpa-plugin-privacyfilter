package payload_test

// Two questions the previous run raised:
//  1. does a body with trailing whitespace reach the forward path at all,
//     given that on_error is block there?
//  2. what happens to a lone surrogate, which is legal JSON but not legal
//     UTF-8, when the body is re-serialized?

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// A real HTTP body often ends in a newline. If ReplaceStrings rejects it,
// every such request is blocked on the forward path.
func TestReplaceStrings_TrailingWhitespace(t *testing.T) {
	cases := map[string]string{
		"newline":       `{"a":"zeus.lan"}` + "\n",
		"crlf":          `{"a":"zeus.lan"}` + "\r\n",
		"space":         `{"a":"zeus.lan"} `,
		"leading space": ` {"a":"zeus.lan"}`,
		"tab around":    "\t" + `{"a":"zeus.lan"}` + "\t",
		"clean":         `{"a":"zeus.lan"}`,
	}
	for name, body := range cases {
		out, n, err := payload.ReplaceStrings([]byte(body), payload.DefaultDeny(), replaceHost)
		t.Logf("%-14s -> replaced=%d err=%v out=%q", name, n, err, string(out))
		if err != nil {
			t.Errorf("%s: a body with surrounding whitespace was rejected: %v", name, err)
		}
	}
}

// Control characters must stay escaped, or the body becomes invalid JSON.
func TestWalk_ControlCharacters(t *testing.T) {
	body := `{"ctl":"a\u0001b\u001fc","hit":"zeus.lan"}`
	out, _, err := payload.Walk([]byte(body), payload.WalkOptions{}, replaceHost)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if strings.ContainsAny(string(out), "\x01\x1f") {
		t.Errorf("control characters were emitted raw, the body is no longer valid JSON: %q", out)
	}
	t.Logf("out=%s", out)
}
