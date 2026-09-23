package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// assertBlocked checks that buildPlugin registered the plugin in the blocking
// state: no error from the registration, only the request interceptor
// announced, and every request terminated with status 400 and a message that
// carries each of want. It returns the message, so the caller can check what
// it must not carry.
//
// The state exists because a failed registration is worse than a blocked
// proxy: the host comes up without the filter, logs one line, and forwards
// every request in clear text. A blocked request reaches the user in the
// client at once.
func assertBlocked(t *testing.T, plugin pluginapi.Plugin, err error, want ...string) string {
	t.Helper()
	if err != nil {
		t.Fatalf("buildPlugin returned %v, want a registration in the blocking state", err)
	}
	if plugin.Capabilities.RequestInterceptor == nil {
		t.Fatal("a blocked plugin announces no request interceptor")
	}
	if plugin.Capabilities.ResponseInterceptor != nil || plugin.Capabilities.StreamChunkInterceptor != nil || plugin.Capabilities.RequestLifecyclePlugin != nil {
		t.Error("a blocked plugin announces more than the request interceptor")
	}
	resp, errReq := plugin.Capabilities.RequestInterceptor.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID:    "req-blocked",
		SourceFormat: "claude",
		Model:        "claude-fable-5-1",
		Headers:      http.Header{},
		Body:         []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"hello"}]}`),
	})
	if errReq != nil {
		t.Fatalf("a blocked request returned an error instead of a terminated response: %v", errReq)
	}
	if !resp.Terminate || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("blocked request: terminate=%v status=%d, want a terminated 400", resp.Terminate, resp.StatusCode)
	}
	var apiErr apiError
	if err := json.Unmarshal(resp.ResponseBody, &apiErr); err != nil {
		t.Fatalf("the blocked response is not an Anthropic-shaped error: %v: %s", err, resp.ResponseBody)
	}
	message := apiErr.Error.Message
	if !strings.Contains(message, "every request is blocked until the configuration is fixed") {
		t.Errorf("the client message %q does not say that every request is blocked", message)
	}
	for _, w := range want {
		if !strings.Contains(message, w) {
			t.Errorf("the client message %q does not carry %q", message, w)
		}
	}
	return message
}

// A skipped model or format passes a working plugin unfiltered by the user's
// choice. A blocked plugin filters nothing, so the skip lists do not apply:
// the request is blocked like any other.
func TestBlocked_SkipListsDoNotApply(t *testing.T) {
	dir := t.TempDir()
	cfgYAML := "mode: pseudonymize\nskip_models: [claude-fable-5-1]\nskip_formats: [claude]\n"
	plugin, err := buildPlugin([]byte(cfgYAML), dir, nil)
	assertBlocked(t, plugin, err, "secret")
}
