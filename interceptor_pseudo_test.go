package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

// newPseudoPlugin builds the plugin from a YAML document the way the host does,
// with a secret file in a temporary directory. override replaces top-level keys
// of the document, so a single test can switch mode, on_error or the limits.
func newPseudoPlugin(t *testing.T, override map[string]any) *privacyFilterPlugin {
	t.Helper()

	dir := t.TempDir()
	secretPath := filepath.Join(dir, pseudo.DefaultSecretFile)
	secret := append(append([]byte{}, fixtures.Secret...), '\n')
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	terms := make([]any, 0, len(fixtures.Terms))
	for _, term := range fixtures.Terms {
		entry := map[string]any{"kind": string(term.Kind)}
		if term.Value != "" {
			entry["value"] = term.Value
		} else {
			entry["regex"] = term.Regex
		}
		if term.IgnoreCase {
			entry["ignore_case"] = true
		}
		terms = append(terms, entry)
	}

	doc := map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": secretPath,
		"terms":            terms,
		"patterns": map[string]any{
			"ipv4": true, "ipv6": true, "cidr": true,
			"mac": true, "email": true, "iban": true, "url": false,
		},
		"packyme":  map[string]any{"enabled": true},
		"path":     map[string]any{"enabled": true, "replace_unknown": true},
		"on_error": string(OnErrorBlock),
	}
	for k, v := range override {
		doc[k] = v
	}

	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	plug, err := buildPlugin(raw, dir, nil)
	if err != nil {
		t.Fatalf("buildPlugin: %v", err)
	}
	p, ok := plug.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !ok {
		t.Fatalf("RequestInterceptor is %T, want *privacyFilterPlugin", plug.Capabilities.RequestInterceptor)
	}
	return p
}

// fixtureBody marshals the shared request fixture.
func fixtureBody(t *testing.T, session string) ([]byte, map[string]any) {
	t.Helper()
	req := fixtures.Request(session)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return body, req
}

// thinkingText returns the text of the thinking block of the fixture, read from
// the fixture itself so the test does not hard-code a value that lives there.
func thinkingText(t *testing.T, req map[string]any) string {
	t.Helper()
	messages, ok := req["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatal("fixture has no assistant turn")
	}
	blocks, ok := messages[1].(map[string]any)["content"].([]any)
	if !ok || len(blocks) == 0 {
		t.Fatal("fixture assistant turn has no blocks")
	}
	text, ok := blocks[0].(map[string]any)["thinking"].(string)
	if !ok {
		t.Fatal("fixture assistant turn has no thinking block")
	}
	return text
}

func jsonString(t *testing.T, s string) []byte {
	t.Helper()
	enc, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal %q: %v", s, err)
	}
	return enc
}

func beforeAuth(t *testing.T, p *privacyFilterPlugin, requestID string, body []byte) pluginapi.RequestInterceptResponse {
	t.Helper()
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID:    requestID,
		SourceFormat: "claude",
		Model:        "claude-fable-5-1",
		Headers:      http.Header{},
		Body:         body,
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth: %v", err)
	}
	return resp
}

// TestPseudonymizeRequest_NoCorpusValueSurvives is the leak test on the
// interceptor: no confidential value of the corpus may leave in the rewritten
// body.
//
// Two regions are cut out of the search before it runs, because the contract
// preserves them byte for byte and both contain corpus text on purpose: the
// thinking block, which the deny list excludes as a whole, and the benign
// message, whose look-alikes ("Markusplatz" contains the person term "markus")
// must survive untouched. Everything else has to be clean. See the disagreement
// noted for internal/leaktest, which asserts both properties over the whole
// body at once.
func TestPseudonymizeRequest_NoCorpusValueSurvives(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, req := fixtureBody(t, fixtures.SessionA)

	resp := beforeAuth(t, p, "req-1", body)
	if resp.Terminate {
		t.Fatalf("request terminated: %s", resp.ResponseBody)
	}
	if len(resp.Body) == 0 {
		t.Fatal("expected a rewritten body, got none")
	}
	if !json.Valid(resp.Body) {
		t.Fatalf("rewritten body is not valid JSON: %s", resp.Body)
	}

	preserved := jsonString(t, thinkingText(t, req))
	benign := jsonString(t, fixtures.Benign)
	scan := bytes.ReplaceAll(resp.Body, preserved, []byte(`""`))
	scan = bytes.ReplaceAll(scan, benign, []byte(`""`))
	lower := bytes.ToLower(scan)

	for _, term := range fixtures.All() {
		haystack, needle := scan, []byte(term.Value)
		if term.IgnoreCase {
			haystack, needle = lower, []byte(strings.ToLower(term.Value))
		}
		if bytes.Contains(haystack, needle) {
			t.Errorf("%s %q leaked", term.Kind, term.Value)
		}
		escaped := jsonString(t, term.Value)
		if bytes.Contains(scan, escaped[1:len(escaped)-1]) {
			t.Errorf("%s %q leaked in escaped form", term.Kind, term.Value)
		}
	}

	// The system prompt and the tool description are fields the original
	// plugin never looked at.
	for _, s := range []string{"Markus Wendler", "athene.lan", "10.13.0.0/16", "helios-nas-01"} {
		if bytes.Contains(scan, []byte(s)) {
			t.Errorf("%q survived in the system prompt or the tool description", s)
		}
	}
}

// TestPseudonymizeRequest_DeniedFieldsUntouched: the thinking block with its
// signature, metadata.user_id and the benign message come back unchanged.
func TestPseudonymizeRequest_DeniedFieldsUntouched(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, req := fixtureBody(t, fixtures.SessionA)
	resp := beforeAuth(t, p, "req-1", body)

	thinking := jsonString(t, thinkingText(t, req))
	for _, want := range [][]byte{
		append([]byte(`"thinking":`), thinking...),
		[]byte(`"signature":"` + fixtures.ThinkingSignature + `"`),
		[]byte(`"user_id":"` + fixtures.UserIDFor(fixtures.SessionA) + `"`),
		[]byte(`"id":"` + fixtures.ToolUseID + `"`),
		[]byte(`"tool_use_id":"` + fixtures.ToolUseID + `"`),
		[]byte(`"name":"Bash"`),
		[]byte(`"model":"claude-fable-5-1"`),
		jsonString(t, fixtures.Benign),
	} {
		if !bytes.Contains(resp.Body, want) {
			t.Errorf("denied field changed or lost: %s", want)
		}
	}
}

// TestPseudonymizeRequest_StoresTable: the mapping table lands under the
// RequestID, and it is stored even when nothing was replaced.
func TestPseudonymizeRequest_StoresTable(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-1", body)

	table, err := p.store.Get("req-1")
	if err != nil {
		t.Fatalf("store.Get(req-1): %v", err)
	}
	if table.Len() == 0 {
		t.Fatal("stored table is empty")
	}

	clean := []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"Der Plan steht."}]}`)
	resp := beforeAuth(t, p, "req-2", clean)
	if resp.Body != nil {
		t.Fatalf("expected no rewrite for a clean body, got: %s", resp.Body)
	}
	empty, err := p.store.Get("req-2")
	if err != nil {
		t.Fatalf("store.Get(req-2): %v", err)
	}
	if empty.Len() != 0 {
		t.Fatalf("table for a clean body has %d entries, want 0", empty.Len())
	}
}

// TestPseudonymizeRequest_AfterAuthEmpty: the body is walked once, in the
// hook before authentication.
func TestPseudonymizeRequest_AfterAuthEmpty(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)

	resp, err := p.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID:    "req-1",
		SourceFormat: "claude",
		Body:         body,
	})
	if err != nil {
		t.Fatalf("InterceptRequestAfterAuth: %v", err)
	}
	if resp.Body != nil || resp.Terminate || resp.StatusCode != 0 || resp.ResponseBody != nil {
		t.Fatalf("expected an empty response, got %+v", resp)
	}
	if p.store.Len() != 0 {
		t.Fatalf("AfterAuth stored %d tables, want 0", p.store.Len())
	}
}

// TestPseudonymizeRequest_SessionSources: header and metadata.user_id name the
// same conversation, so both give the same pseudonyms; another conversation
// gives different ones.
func TestPseudonymizeRequest_SessionSources(t *testing.T) {
	p := newPseudoPlugin(t, nil)

	viaMetadata, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-1", viaMetadata)

	noSession, _ := fixtureBody(t, "")
	headers := http.Header{}
	headers.Set(pseudo.SessionHeader, fixtures.SessionA)
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID:    "req-2",
		SourceFormat: "claude",
		Headers:      headers,
		Body:         noSession,
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth: %v", err)
	}

	a, _ := p.store.Get("req-1")
	b, _ := p.store.Get("req-2")
	for _, e := range a.Entries() {
		if got := b.Lookup(e.Kind, e.Original); got != e.Pseudonym {
			t.Errorf("%s: header session gives %q, metadata session gave %q", e.Kind, got, e.Pseudonym)
		}
	}
	if !json.Valid(resp.Body) {
		t.Fatalf("rewritten body is not valid JSON: %s", resp.Body)
	}

	other, _ := fixtureBody(t, fixtures.SessionB)
	beforeAuth(t, p, "req-3", other)
	c, _ := p.store.Get("req-3")
	same := 0
	for _, e := range a.Entries() {
		if c.Lookup(e.Kind, e.Original) == e.Pseudonym {
			same++
		}
	}
	if same != 0 {
		t.Fatalf("%d pseudonyms identical across two conversations", same)
	}
}

// TestPseudonymizeRequest_Deterministic: the same body twice gives the same
// bytes, so the thinking-block signatures of a conversation stay valid.
func TestPseudonymizeRequest_Deterministic(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	first := beforeAuth(t, p, "req-1", body)
	second := beforeAuth(t, p, "req-2", body)
	if !bytes.Equal(first.Body, second.Body) {
		t.Fatal("two forward passes over the same body differ")
	}
}

// TestPseudonymizeRequest_RealShapedToken is the positive control for the
// credential layer: a token of the documented shape and full entropy is
// replaced. The value is assembled from parts so this file never contains a
// complete token literal, as internal/fixtures does it.
func TestPseudonymizeRequest_RealShapedToken(t *testing.T) {
	token := "gh" + "p_" + "Xk9mQ2vTb7YpLz4Rw8NcHs5JdFg1AeUi3Bo0"
	req := map[string]any{
		"model":    "claude-fable-5-1",
		"messages": []any{map[string]any{"role": "user", "content": "Der Token lautet " + token + " und gehört rotiert."}},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	p := newPseudoPlugin(t, nil)
	resp := beforeAuth(t, p, "req-1", body)
	if bytes.Contains(resp.Body, []byte(token)) {
		t.Fatalf("the credential survived: %s", resp.Body)
	}
	if !bytes.Contains(resp.Body, []byte(pseudo.PrefixSecret)) {
		t.Fatalf("expected an opaque secret pseudonym, got: %s", resp.Body)
	}
}

// TestPseudonymizeRequest_SecondPassOnlyTouchesRecompositions states what
// idempotence currently amounts to: no original value is detected a second
// time, because Exclude knows every pseudonym, but a replacement can compose a
// new structural value out of pseudonyms.
//
// The corpus has one such case. "markus@wendler.de" is covered by two entries
// of the maintained list, the person "markus" and the domain "wendler.de", and
// the maintained list wins over the structural email pattern by design, so the
// address comes out as "<name>@d-<hex>.invalid" - itself a well-formed address
// that the email pattern then finds on a second pass. The forward path is
// unaffected, since a client never sends pseudonyms back: the return path
// restores the originals first. This test therefore asserts the property that
// holds, and it is the reason TestIdempotent in internal/leaktest fails.
func TestPseudonymizeRequest_SecondPassOnlyTouchesRecompositions(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	first := beforeAuth(t, p, "req-1", body)
	second := beforeAuth(t, p, "req-2", first.Body)

	before, err := p.store.Get("req-1")
	if err != nil {
		t.Fatalf("store.Get(req-1): %v", err)
	}
	after, err := p.store.Get("req-2")
	if err != nil {
		t.Fatalf("store.Get(req-2): %v", err)
	}

	if after.Len() == 0 {
		if second.Body != nil && !bytes.Equal(first.Body, second.Body) {
			t.Fatal("the second pass replaced nothing but changed the body")
		}
		return
	}

	pseudonyms := before.Pseudonyms()
	for _, e := range after.Entries() {
		recomposed := false
		for _, ps := range pseudonyms {
			if strings.Contains(e.Original, ps) {
				recomposed = true
				break
			}
		}
		if !recomposed {
			t.Errorf("the second pass replaced %s %q, which carries no pseudonym of the first pass", e.Kind, e.Original)
		}
	}
}

// TestPseudonymizeRequest_BlocksNonJSON: on_error block terminates with an
// Anthropic-shaped error body.
func TestPseudonymizeRequest_BlocksNonJSON(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	resp := beforeAuth(t, p, "req-1", []byte("not valid json, athene.lan"))

	if !resp.Terminate {
		t.Fatal("expected the request to be terminated")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := resp.ResponseHeaders.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}
	var errBody apiError
	if err := json.Unmarshal(resp.ResponseBody, &errBody); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if errBody.Type != "error" || errBody.Error.Type != "invalid_request_error" {
		t.Fatalf("unexpected error shape: %+v", errBody)
	}
	if !strings.HasPrefix(errBody.Error.Message, "privacyfilter: ") {
		t.Fatalf("message = %q, want a privacyfilter prefix", errBody.Error.Message)
	}
	if strings.Contains(string(resp.ResponseBody), "athene.lan") {
		t.Fatal("the error body echoes the request body")
	}
	if p.store.Len() != 0 {
		t.Fatalf("a blocked request stored %d tables, want 0", p.store.Len())
	}
}

// TestPseudonymizeRequest_PassthroughNonJSON: on_error passthrough forwards the
// body unfiltered, as the original plugin always did.
func TestPseudonymizeRequest_PassthroughNonJSON(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{"on_error": string(OnErrorPassthrough)})
	resp := beforeAuth(t, p, "req-1", []byte("not valid json, athene.lan"))
	if resp.Terminate || resp.Body != nil || resp.ResponseBody != nil {
		t.Fatalf("expected an empty response, got %+v", resp)
	}
}

// TestPseudonymizeRequest_BlocksOversizeBody: a body over the configured limit
// is blocked rather than forwarded unfiltered.
func TestPseudonymizeRequest_BlocksOversizeBody(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{
		"limits": map[string]any{"max_body_bytes": 512, "mapping_ttl": "10m"},
	})
	body, _ := fixtureBody(t, fixtures.SessionA)
	if len(body) <= 512 {
		t.Fatalf("fixture body is only %d bytes, the limit no longer bites", len(body))
	}
	resp := beforeAuth(t, p, "req-1", body)
	if !resp.Terminate || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected a 400 termination, got %+v", resp)
	}
	var errBody apiError
	if err := json.Unmarshal(resp.ResponseBody, &errBody); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if !strings.Contains(errBody.Error.Message, "size limit") {
		t.Fatalf("message = %q, want the size limit named", errBody.Error.Message)
	}
}

// TestPseudonymizeRequest_SkipFormat: skip_formats still short-circuits before
// anything is touched.
func TestPseudonymizeRequest_SkipFormat(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{"skip_formats": []any{"claude"}})
	body, _ := fixtureBody(t, fixtures.SessionA)
	resp := beforeAuth(t, p, "req-1", body)
	if resp.Body != nil || resp.Terminate {
		t.Fatalf("expected a skipped format to pass through, got %+v", resp)
	}
	if p.store.Len() != 0 {
		t.Fatalf("a skipped request stored %d tables, want 0", p.store.Len())
	}
}

// TestBuildPlugin_MissingSecretFails: registration fails when the secret file
// is absent, so the plugin never silently forwards plain text.
func TestBuildPlugin_MissingSecretFails(t *testing.T) {
	dir := t.TempDir()
	raw, err := yaml.Marshal(map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": filepath.Join(dir, pseudo.DefaultSecretFile),
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if _, err := buildPlugin(raw, dir, nil); err == nil {
		t.Fatal("expected registration to fail without a secret file")
	}
}

// TestBuildPlugin_ShortSecretFails: a secret below pseudo.MinSecretLen is
// refused at registration.
func TestBuildPlugin_ShortSecretFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pseudo.DefaultSecretFile)
	if err := os.WriteFile(path, []byte("too short\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	raw, err := yaml.Marshal(map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": path,
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	_, err = buildPlugin(raw, dir, nil)
	if err == nil {
		t.Fatal("expected registration to fail on a short secret")
	}
	if !strings.Contains(err.Error(), "32") {
		t.Fatalf("error = %v, want the minimum length named", err)
	}
}

// TestBuildPlugin_InvalidTermKindFails: an unknown kind in terms[] is caught at
// registration, not at the first request.
func TestBuildPlugin_InvalidTermKindFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pseudo.DefaultSecretFile)
	if err := os.WriteFile(path, fixtures.Secret, 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	raw, err := yaml.Marshal(map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": path,
		"terms":            []any{map[string]any{"value": "athene.lan", "kind": "hostname"}},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if _, err := buildPlugin(raw, dir, nil); err == nil {
		t.Fatal("expected registration to fail on an invalid term kind")
	}
}

// TestBuildPlugin_PseudonymShapedTermFails: a literal that is its own
// pseudonym would never be replaced, so registration refuses it. The
// composite excludes pseudonym shapes from detection, which is what keeps the
// forward pass idempotent, and the wiring is where the pseudo package
// delegates the check.
func TestBuildPlugin_PseudonymShapedTermFails(t *testing.T) {
	cases := []struct {
		name  string
		value string
		kind  string
		ok    bool
	}{
		{"cgnat address", "100.100.1.1", "ipv4", false},
		{"cgnat network", "100.64.0.0/10", "cidr", false},
		{"marker ula", "fdff:5046:5346::1", "ipv6", false},
		{"host shaped", "h-0123456789ab", "host", false},
		{"ordinary address", "10.13.7.42", "ipv4", true},
		{"ordinary person", "markus", "person", true},
		// A term equal to a built-in name is not refused: the entry is left
		// out of the list for this plugin, whatever kind the term declares.
		{"built-in person", pseudo.Names[0], "person", true},
		{"built-in given name", strings.Fields(pseudo.Names[0])[0], "person", true},
		{"name as host", pseudo.Names[0], "host", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, pseudo.DefaultSecretFile)
			if err := os.WriteFile(path, fixtures.Secret, 0o600); err != nil {
				t.Fatalf("write secret: %v", err)
			}
			raw, err := yaml.Marshal(map[string]any{
				"mode":             string(ModePseudonymize),
				"salt_secret_path": path,
				"terms":            []any{map[string]any{"value": tc.value, "kind": tc.kind}},
			})
			if err != nil {
				t.Fatalf("marshal config: %v", err)
			}
			_, err = buildPlugin(raw, dir, nil)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("buildPlugin(%q %s) = %v, want success", tc.value, tc.kind, err)
			case !tc.ok && err == nil:
				t.Fatalf("buildPlugin(%q %s) succeeded, want a refusal", tc.value, tc.kind)
			case !tc.ok && !strings.Contains(err.Error(), "shape of a pseudonym"):
				t.Fatalf("buildPlugin(%q %s) = %v, want the shape refusal", tc.value, tc.kind, err)
			}
		})
	}
}

// TestBuildPlugin_SecretsLayerUnavailable: without the betterleaks build tag,
// secrets.enabled aborts registration instead of pretending to scan.
func TestBuildPlugin_SecretsLayerUnavailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pseudo.DefaultSecretFile)
	if err := os.WriteFile(path, fixtures.Secret, 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	raw, err := yaml.Marshal(map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": path,
		"secrets":          map[string]any{"enabled": true},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	_, err = buildPlugin(raw, dir, nil)
	if err == nil {
		// Only a binary built with the betterleaks tag gets here.
		return
	}
	if !errors.Is(err, detect.ErrSecretsUnavailable) {
		t.Fatalf("error = %v, want detect.ErrSecretsUnavailable", err)
	}
}

// TestRedactMode_Unchanged: the default mode keeps the original behaviour, and
// none of the pseudonymize machinery is built.
func TestRedactMode_Unchanged(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{"mode": string(ModeRedact)})
	if p.store != nil || p.layers != nil || p.secret != nil || p.deny != nil {
		t.Fatal("redact mode built pseudonymize state")
	}

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`)
	for _, hook := range []struct {
		name string
		call func(context.Context, pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error)
	}{
		{"BeforeAuth", p.InterceptRequestBeforeAuth},
		{"AfterAuth", p.InterceptRequestAfterAuth},
	} {
		resp, err := hook.call(context.Background(), pluginapi.RequestInterceptRequest{
			RequestID: "req-1",
			Model:     "gpt-4",
			Body:      body,
		})
		if err != nil {
			t.Fatalf("%s: %v", hook.name, err)
		}
		if resp.Terminate {
			t.Fatalf("%s: redact mode must never terminate a request", hook.name)
		}
		if !strings.Contains(string(resp.Body), "[邮箱]") {
			t.Fatalf("%s: expected the redaction placeholder, got: %s", hook.name, resp.Body)
		}
		if strings.Contains(string(resp.Body), "test@example.com") {
			t.Fatalf("%s: the original email survived", hook.name)
		}
	}

	// Invalid JSON stays a pass-through in redact mode, whatever on_error says.
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		Body: []byte("not valid json with email test@example.com"),
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth: %v", err)
	}
	if resp.Terminate || resp.Body != nil {
		t.Fatalf("expected a pass-through, got %+v", resp)
	}
}
