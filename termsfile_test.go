package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseTermsFile_Forms(t *testing.T) {
	in := strings.Join([]string{
		"# maintained list",
		"",
		"p14.local",
		"p14 host   # short name",
		"markus person ignore_case",
		"wendler.de domain",
		`{regex: "[a-z0-9-]+\\.home\\.lan", kind: host}`,
		`{value: "Max Muster", kind: person, ignore_case: true}`,
		`{value: "10.13.0.0/16", kind: cidr}   # comment after yaml`,
		"  ",
	}, "\n")
	got, err := parseTermsFile(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseTermsFile: %v", err)
	}
	want := []TermEntry{
		{Value: "p14.local", Kind: "host"},
		{Value: "p14", Kind: "host"},
		{Value: "markus", Kind: "person", IgnoreCase: true},
		{Value: "wendler.de", Kind: "domain"},
		{Regex: `[a-z0-9-]+\.home\.lan`, Kind: "host"},
		{Value: "Max Muster", Kind: "person", IgnoreCase: true},
		{Value: "10.13.0.0/16", Kind: "cidr"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTermsFile =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseTermsFile_Errors(t *testing.T) {
	for _, in := range []string{
		"p14 host extra",
		"p14 host person",
		"{value: p14, kinds: host}",
		"{value: p14, kind: host",
		"p14 host ignore_case ignore_case",
	} {
		if _, err := parseTermsFile(strings.NewReader(in)); err == nil {
			t.Errorf("parseTermsFile(%q) accepted", in)
		} else if !strings.Contains(err.Error(), "line 1") {
			t.Errorf("parseTermsFile(%q) error %q does not name the line", in, err)
		}
	}
}

func TestMergeTerms_DedupKeepsFirst(t *testing.T) {
	inline := []TermEntry{{Value: "p14", Kind: "host"}, {Value: "markus", Kind: "person", IgnoreCase: true}}
	file := []TermEntry{{Value: "p14", Kind: "host"}, {Value: "p14", Kind: "person"}, {Value: "nuc", Kind: "host"}}
	got := mergeTerms(inline, file)
	want := []TermEntry{inline[0], inline[1], file[1], file[2]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeTerms = %+v, want %+v", got, want)
	}
}

func TestResolveTermsFilePath(t *testing.T) {
	if got := resolveTermsFilePath("/plugins", ""); got != "" {
		t.Fatalf("empty -> %q", got)
	}
	if got := resolveTermsFilePath("/plugins", "terms.txt"); got != filepath.Join("/plugins", "terms.txt") {
		t.Fatalf("relative -> %q", got)
	}
	if got := resolveTermsFilePath("/plugins", "/etc/terms.txt"); got != "/etc/terms.txt" {
		t.Fatalf("absolute -> %q", got)
	}
}

func TestLoadTermsFile_MissingAndInvalid(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadTermsFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Fatal("missing file accepted")
	}
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("ok host\nbroken host extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadTermsFile(bad)
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), bad) {
		t.Fatalf("loadTermsFile error = %v, want path and line 2", err)
	}
}

// TestPseudonymize_TermsFileMerged builds the plugin with an inline term and
// a term file and checks that both are applied and that a broken file refuses
// registration.
func TestPseudonymize_TermsFileMerged(t *testing.T) {
	dir := t.TempDir()
	termsPath := filepath.Join(dir, "terms.txt")
	if err := os.WriteFile(termsPath, []byte("# hosts\np14.local\np14 host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newPseudoPlugin(t, map[string]any{
		"terms":      []any{map[string]any{"value": "nuc", "kind": "host"}},
		"terms_file": termsPath,
	})
	if p.termCount != 3 {
		t.Fatalf("termCount = %d, want 3", p.termCount)
	}
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"ssh p14.local; ssh p14; ssh nuc; p140 bleibt"}]}`)
	res, err := p.runForward(nil, body)
	if err != nil {
		t.Fatalf("runForward: %v", err)
	}
	out := string(res.out)
	for _, leaked := range []string{"p14.local", "ssh p14;", "ssh nuc"} {
		if strings.Contains(out, leaked) {
			t.Errorf("%q survived: %s", leaked, out)
		}
	}
	if !strings.Contains(out, "p140 bleibt") {
		t.Errorf("word boundary broken: %s", out)
	}

	if err := os.WriteFile(termsPath, []byte("p14 host extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgYAML := "mode: pseudonymize\nsalt_secret_path: " + filepath.Join(dir, "s.secret") + "\nterms_file: " + termsPath + "\n"
	if err := os.WriteFile(filepath.Join(dir, "s.secret"), []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildPlugin([]byte(cfgYAML), dir, nil); err == nil || !strings.Contains(err.Error(), "terms_file") {
		t.Fatalf("buildPlugin with a broken terms file: err = %v, want a terms_file error", err)
	}
}
