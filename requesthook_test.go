package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// The host forwards the original body when a request hook returns an error
// (internal/pluginhost/adapters_interceptors.go, callRequestInterceptor and
// interceptRequest, at v7.3.15 and v8.0.75). These tests hold that the two
// request hooks answer every failure under on_error instead.

// saveABIState restores the library state a test changes.
func saveABIState(t *testing.T) {
	t.Helper()
	privacyFilterABIState.Lock()
	host := privacyFilterABIState.host
	plugin := privacyFilterABIState.plugin
	shuttingDown := privacyFilterABIState.shuttingDown
	onError := privacyFilterABIState.onError
	privacyFilterABIState.Unlock()
	t.Cleanup(func() {
		privacyFilterABIState.Lock()
		privacyFilterABIState.host = host
		privacyFilterABIState.plugin = plugin
		privacyFilterABIState.shuttingDown = shuttingDown
		privacyFilterABIState.onError = onError
		privacyFilterABIState.Unlock()
	})
}

// registerForHookTest registers an instance in redact mode, with on_error set
// when onError is not empty.
func registerForHookTest(t *testing.T, onError string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = \"request hook test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := "gitleaks_toml: rules.toml\n"
	if onError != "" {
		config += "on_error: " + onError + "\n"
	}
	if _, err := handlePrivacyFilterRegister(context.Background(), pluginabi.MethodPluginRegister, registerRequest(t, dir, config)); err != nil {
		t.Fatalf("register: %v", err)
	}
}

// decodeHookResponse decodes what a request hook hands to the host. An error
// or an error envelope fails the test, because the host forwards the original
// body on either.
func decodeHookResponse(t *testing.T, raw []byte, err error) pluginapi.RequestInterceptResponse {
	t.Helper()
	if err != nil {
		t.Fatalf("request hook returned an error, the host would forward the original body: %v", err)
	}
	var envelope abiEnvelope
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil {
		t.Fatalf("envelope: %v", errDecode)
	}
	if !envelope.OK {
		t.Fatalf("request hook returned an error envelope, the host would forward the original body: %s", raw)
	}
	var resp pluginapi.RequestInterceptResponse
	if errDecode := json.Unmarshal(envelope.Result, &resp); errDecode != nil {
		t.Fatalf("result: %v", errDecode)
	}
	return resp
}

// assertHookBlocked holds a terminated request with the status, the error type of
// the Messages API for it, and the reason.
func assertHookBlocked(t *testing.T, resp pluginapi.RequestInterceptResponse, status int, errType, reason string) {
	t.Helper()
	if !resp.Terminate || resp.StatusCode != status {
		t.Fatalf("want terminate with %d, got terminate=%v status=%d", status, resp.Terminate, resp.StatusCode)
	}
	var body apiError
	if err := json.Unmarshal(resp.ResponseBody, &body); err != nil {
		t.Fatalf("error body: %v", err)
	}
	if body.Error.Type != errType || !strings.Contains(body.Error.Message, reason) {
		t.Fatalf("want %s with %q, got %+v", errType, reason, body.Error)
	}
}

// assertForwarded holds an empty answer: no termination and no body, so the
// host goes on with the body it has, which is what passthrough asks for.
func assertForwarded(t *testing.T, resp pluginapi.RequestInterceptResponse) {
	t.Helper()
	if resp.Terminate || len(resp.Body) != 0 || len(resp.ResponseBody) != 0 {
		t.Fatalf("want an empty answer under passthrough, got %+v", resp)
	}
}

var requestHooks = []string{pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter}

func TestRequestHooksAnswerAnUnreadablePayloadUnderOnError(t *testing.T) {
	payloads := map[string][]byte{
		"type mismatch": []byte(`{"headers":{"X-Probe":"marker-value-1"}}`),
		"truncated":     []byte(`{"body":`),
		"empty":         nil,
	}
	for _, onError := range []string{"", "block", "passthrough"} {
		t.Run("on_error="+onError, func(t *testing.T) {
			saveABIState(t)
			registerForHookTest(t, onError)
			for _, method := range requestHooks {
				for name, payload := range payloads {
					raw, err := handlePrivacyFilterABIMethod(context.Background(), method, payload)
					resp := decodeHookResponse(t, raw, err)
					if onError == "passthrough" {
						assertForwarded(t, resp)
						continue
					}
					assertHookBlocked(t, resp, http.StatusBadRequest, "invalid_request_error", "cannot read")
					if strings.Contains(string(resp.ResponseBody), "marker-value-1") {
						t.Fatalf("%s %s: the error body carries a byte of the payload", method, name)
					}
				}
			}
		})
	}
}

func TestRequestHooksBlockWhileThePluginIsUnavailable(t *testing.T) {
	ctx := context.Background()
	payload := []byte(`{"body":"e30="}`)

	t.Run("never registered", func(t *testing.T) {
		saveABIState(t)
		privacyFilterABIState.Lock()
		privacyFilterABIState.plugin = nil
		privacyFilterABIState.shuttingDown = false
		privacyFilterABIState.onError = ""
		privacyFilterABIState.Unlock()
		for _, method := range requestHooks {
			raw, err := handlePrivacyFilterABIMethod(ctx, method, payload)
			assertHookBlocked(t, decodeHookResponse(t, raw, err), http.StatusServiceUnavailable, "api_error", "not ready")
		}
	})

	for _, onError := range []string{"block", "passthrough"} {
		t.Run("shutting down after on_error="+onError, func(t *testing.T) {
			saveABIState(t)
			registerForHookTest(t, onError)
			PrivacyFilterPluginShutdown()
			for _, method := range requestHooks {
				raw, err := handlePrivacyFilterABIMethod(ctx, method, payload)
				resp := decodeHookResponse(t, raw, err)
				if onError == "passthrough" {
					assertForwarded(t, resp)
					continue
				}
				assertHookBlocked(t, resp, http.StatusServiceUnavailable, "api_error", "not ready")
			}
			// The return path keeps its error: it passes through on error by
			// design, and the host does the same with an error from it.
			if _, err := handlePrivacyFilterABIMethod(ctx, pluginabi.MethodResponseInterceptAfter, []byte(`{}`)); err == nil {
				t.Fatal("response hook must still report that the plugin is shutting down")
			}
		})
	}
}

func TestDecodeErrorClassCarriesNoPayload(t *testing.T) {
	var req abiRequestInterceptRequest
	err := json.Unmarshal([]byte(`{"headers":{"X-Probe":"marker-value-1"}}`), &req)
	if err == nil {
		t.Fatal("want a type mismatch")
	}
	class := decodeErrorClass(err)
	if strings.Contains(class, "marker-value-1") || !strings.Contains(class, "JSON string") {
		t.Fatalf("class %q must name the JSON kind and not the value", class)
	}
	err = json.Unmarshal([]byte(`{"body":"marker-value-1`), &req)
	if class = decodeErrorClass(err); strings.Contains(class, "marker") {
		t.Fatalf("class %q must not carry the payload", class)
	}
}
