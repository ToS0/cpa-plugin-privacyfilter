package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// TestAudit_RecordsTableAndRestores: with audit.path set, the forward pass
// writes the mapping table, the return path's swaps are counted, and the
// completion writes them out; the file is created with mode 0600.
func TestAudit_RecordsTableAndRestores(t *testing.T) {
	dir := t.TempDir()
	p := newPseudoPlugin(t, map[string]any{"audit": map[string]any{"path": "audit.log"}})
	// newPseudoPlugin's plugin dir is its own temp dir; the relative path
	// must have resolved there.
	if p.audit == nil || filepath.Base(p.audit.path) != "audit.log" || filepath.Dir(p.audit.path) == dir {
		t.Fatalf("audit = %+v, want a log next to the plugin", p.audit)
	}
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-audit", body)
	table, err := p.store.Get("req-audit")
	if err != nil {
		t.Fatal(err)
	}
	host := table.Lookup(detect.KindHost, "athene.lan")

	// A non-streamed response that repeats the host pseudonym twice.
	resp := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ping ` + host + ` und nochmal ` + host + `"}],"model":"claude-fable-5-1"}`)
	out, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID: "req-audit", SourceFormat: "claude", Model: "claude-fable-5-1", Body: resp, StatusCode: 200,
	})
	if err != nil || !strings.Contains(string(out.Body), "athene.lan") {
		t.Fatalf("response not restored: %v %s", err, out.Body)
	}
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{
		RequestID: "req-audit", Outcome: pluginapi.RequestCompletionSucceeded, Stream: false,
	}); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(p.audit.path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("audit file mode = %o, want 600", st.Mode().Perm())
	}
	raw, err := os.ReadFile(p.audit.path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"\trequest\treq-audit\tformat=claude\tsession=metadata\t",
		"\tmap\treq-audit\thost\tathene.lan\t" + host + "\n",
		"\tmap\treq-audit\tperson\tMarkus\t",
		"\trestored\treq-audit\t" + host + "\tathene.lan\t2\n",
		"\tcomplete\treq-audit\toutcome=succeeded\tstream=false\trestored_distinct=1\trestored_total=2\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("audit log lacks %q\n%s", want, text)
		}
	}
	// Every table row is in the file, none twice.
	for _, e := range table.Entries() {
		line := "\tmap\treq-audit\t" + string(e.Kind) + "\t" + auditField(e.Original) + "\t" + auditField(e.Pseudonym) + "\n"
		if strings.Count(text, line) != 1 {
			t.Errorf("row %q appears %d times", line, strings.Count(text, line))
		}
	}
}

// TestAudit_OffByDefaultAndBadPathFails: no audit without a path, and a
// path in a directory that does not exist refuses registration.
func TestAudit_OffByDefaultAndBadPathFails(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	if p.audit != nil {
		t.Fatal("audit is on without audit.path")
	}
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-noaudit", body)
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{RequestID: "req-noaudit"}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	raw := []byte("mode: pseudonymize\nsalt_secret_path: " + filepath.Join(dir, "pseudonym.secret") + "\naudit:\n  path: " + filepath.Join(dir, "missing", "audit.log") + "\n")
	if err := os.WriteFile(filepath.Join(dir, "pseudonym.secret"), append(append([]byte{}, fixtures.Secret...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildPlugin(raw, dir, nil); err == nil || !strings.Contains(err.Error(), "audit.path") {
		t.Fatalf("buildPlugin error = %v, want an audit.path error", err)
	}
}

// TestAudit_Rotates: a file above max_bytes is moved to ".1" before the
// next write, so the log never grows without bound.
func TestAudit_Rotates(t *testing.T) {
	dir := t.TempDir()
	a, err := newAuditLog(dir, "audit.log", 64)
	if err != nil {
		t.Fatal(err)
	}
	a.write(strings.Repeat("x", 100) + "\n")
	a.write("second\n")
	if _, err := os.Stat(a.path + ".1"); err != nil {
		t.Fatalf("rotated file missing: %v", err)
	}
	raw, _ := os.ReadFile(a.path)
	if string(raw) != "second\n" {
		t.Fatalf("current file = %q, want only the second write", raw)
	}
}

// TestAuditField: values that would break the one-line format are quoted,
// ordinary ones are not.
func TestAuditField(t *testing.T) {
	cases := map[string]string{
		"athene.lan":                          "athene.lan",
		"Ingrid Muster":                       "Ingrid Muster",
		"":                                    `""`,
		"a\tb":                                `"a\tb"`,
		"line\nbreak":                         `"line\nbreak"`,
		" padded":                             `" padded"`,
		"/home/d-2c0ede3ad9e6/d-a7f3fe7a7b53": "/home/d-2c0ede3ad9e6/d-a7f3fe7a7b53",
	}
	for in, want := range cases {
		if got := auditField(in); got != want {
			t.Errorf("auditField(%q) = %q, want %q", in, got, want)
		}
	}
}
