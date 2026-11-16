package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPseudonymizeRequest_SecretAcrossLinesKeepsTheLines runs a finding of
// the generic credential rule across an empty line and a private key block
// through the forward path with the library on, as the server runs it. The
// text keeps its number of line breaks, no line of the key leaves in clear,
// the words after the finding on its last line stay, and the table restores
// the text byte for byte. The key is assembled from invented parts.
func TestPseudonymizeRequest_SecretAcrossLinesKeepsTheLines(t *testing.T) {
	nl := string(rune(10))
	var block strings.Builder
	block.WriteString("-----BEGIN RSA " + "PRIV" + "ATE KEY-----" + nl)
	for i := 0; i < 4; i++ {
		block.WriteString(strings.Repeat("Qm9ndXNLZXk"+string(rune('a'+i)), 6)[:64] + nl)
	}
	block.WriteString("-----END RSA " + "PRIV" + "ATE KEY-----")
	content := "cliproxy" + "api_default" + nl + nl + "== Schnittstelle des Hosts mit der Adresse" + nl + nl + block.String() + nl + "fertig"

	body, err := json.Marshal(map[string]any{
		"model":    "claude-fable-5-1",
		"messages": []any{map[string]any{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := newPseudoPlugin(t, nil)
	resp := beforeAuth(t, p, "req-1", body)
	if resp.Terminate || len(resp.Body) == 0 {
		t.Fatalf("the forward pass did not rewrite: %+v", resp)
	}
	var out struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil || len(out.Messages) != 1 {
		t.Fatalf("unmarshal the rewritten body: %v", err)
	}
	got := out.Messages[0].Content
	if a, b := strings.Count(content, nl), strings.Count(got, nl); a != b {
		t.Errorf("the text had %d line breaks and has %d after the forward pass:\n%s", a, b, got)
	}
	for _, line := range strings.Split(block.String(), nl) {
		if strings.Contains(got, line) {
			t.Errorf("the key line %q left in clear", line)
		}
	}
	if !strings.Contains(got, " des Hosts mit der Adresse") {
		t.Errorf("the words after the finding were taken into it:\n%s", got)
	}
	if back, _ := p.tableOf(t, "req-1").Restorer().Restore(got, false); back != content {
		t.Errorf("the text does not come back byte for byte:\n got %q\nwant %q", back, content)
	}
}
