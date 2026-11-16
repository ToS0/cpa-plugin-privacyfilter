package main

import (
	"context"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// warnings returns the messages of the entries at warning level or above.
func warnings(hook *logtest.Hook) []string {
	var out []string
	for _, e := range hook.AllEntries() {
		if e.Level <= logrus.WarnLevel {
			out = append(out, e.Message)
		}
	}
	return out
}

// TestInterceptResponse_ModelListIsQuiet: the host passes its own model list
// through the response hook with an empty model and requested model and
// neither the original request nor the request body, under a request id the
// forward path never saw (WriteModelListResponse at v8.0.67 and v8.0.75).
// On the server that produced "response for format \"openai\" passed through
// with pseudonyms" twice on the 11th of November, and in the Claude format
// it would produce "no mapping table", the alarm for a table lost across a
// reload. The list carries no pseudonym, so it passes without a word. A
// relayed response keeps both warnings: without a table, and in another
// format.
func TestInterceptResponse_ModelListIsQuiet(t *testing.T) {
	hook := logtest.NewGlobal()
	defer logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))
	p := newPseudoPlugin(t, nil)
	list := []byte(`{"object":"list","data":[{"id":"claude-fable-5-1","object":"model","owned_by":"anthropic"}]}`)

	for _, format := range []string{"openai", "claude"} {
		hook.Reset()
		resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
			RequestID:    "req-model-list-" + format,
			SourceFormat: format,
			Body:         list,
			StatusCode:   200,
		})
		if err != nil {
			t.Fatalf("%s: InterceptResponse: %v", format, err)
		}
		if len(resp.Body) != 0 {
			t.Errorf("%s: the model list was rewritten: %s", format, resp.Body)
		}
		if w := warnings(hook); len(w) != 0 {
			t.Errorf("%s: the model list logged warnings: %q", format, w)
		}
	}

	relayed := func(format string) []string {
		hook.Reset()
		if _, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
			RequestID:       "req-relayed-" + format,
			SourceFormat:    format,
			Model:           "claude-fable-5-1",
			OriginalRequest: []byte(`{"model":"claude-fable-5-1","messages":[]}`),
			Body:            []byte(`{"type":"message","content":[{"type":"text","text":"ok"}]}`),
			StatusCode:      200,
		}); err != nil {
			t.Fatalf("%s: InterceptResponse: %v", format, err)
		}
		return warnings(hook)
	}
	if w := relayed("claude"); len(w) != 1 || !strings.Contains(w[0], "no mapping table") {
		t.Errorf("a relayed response without a table logged %q, want the warning about the missing table", w)
	}
	if w := relayed("openai"); len(w) != 1 || !strings.Contains(w[0], "passed through") {
		t.Errorf("a relayed response in another format logged %q, want the warning about the format", w)
	}

	// The second safeguard: a request id with a table is restored even when
	// the host left all four fields empty, so a later host that stopped
	// filling them would cost a log line, never the restoration.
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-bound", body)
	upstream, _ := upstreamResponse(t, p.tableOf(t, "req-bound"))
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID:    "req-bound",
		SourceFormat: "claude",
		Body:         upstream,
		StatusCode:   200,
	})
	if err != nil || len(resp.Body) == 0 {
		t.Errorf("a bound response without model and request was not restored: %v", err)
	}
}
