package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"golang.org/x/net/http2"
)

const hubNoCredits = "You have no credits remaining. Add credits to continue."

// Billing exhaustion as the OpenAI platform reports it, with and without the
// insufficient_quota code.
func hubBillingForms() map[string]*Error {
	return map[string]*Error{
		"coded":        {HTTPStatus: http.StatusTooManyRequests, Message: `{"error":{"message":"` + hubNoCredits + `","type":"insufficient_quota","code":"insufficient_quota"}}`},
		"message only": {HTTPStatus: http.StatusTooManyRequests, Message: `{"error":{"message":"` + hubNoCredits + `"}}`},
	}
}

func assertBillingHidden(t *testing.T, err error) {
	t.Helper()
	if err == nil || strings.Contains(err.Error(), hubNoCredits) || strings.Contains(err.Error(), "insufficient_quota") {
		t.Fatalf("client error = %v, want the billing failure hidden", err)
	}
}

// P1-a: a paid key's billing exhaustion never reaches the client, whether it
// lacks the insufficient_quota code or arrives after the first stream payload.
func TestHubPaidBillingErrorHidden(t *testing.T) {
	for form, billing := range hubBillingForms() {
		t.Run(form, func(t *testing.T) {
			for _, operation := range []string{"execute", "stream", "count"} {
				t.Run(operation+"/after subscription transport failure", func(t *testing.T) {
					failure := codexTransportFailures()["protocol error"]
					m, executor, call := newHubFallbackTest(t, operation, "codex", 1, "sub", "paid")
					executor.failures["sub"] = []error{failure, failure}
					executor.failures["paid"] = []error{billing}
					assertBillingHidden(t, call())
					assertHubAuthCalls(t, executor, "sub", "sub", "paid")
					if paid, _ := m.GetByID(executor.authIDs["paid"]); paid.Quota.Reason != "credential_quota" {
						t.Fatalf("paid key quota = %+v, want a credential-wide billing cooldown", paid.Quota)
					}
				})
			}
			t.Run("stream/mid-stream", func(t *testing.T) {
				m, executor, call := newHubFallbackTest(t, "stream", "codex", 0, "paid")
				executor.midStream["paid"] = []error{billing}
				assertBillingHidden(t, call())
				if paid, _ := m.GetByID(executor.authIDs["paid"]); paid.Quota.Reason != "credential_quota" {
					t.Fatalf("paid key quota = %+v, want a credential-wide billing cooldown", paid.Quota)
				}
			})
		})
	}
}

// P1-b: a subscription that failed in transport and then hit its quota no
// longer holds the request while the paid key is ready.
func TestHubPaidServesWhenRetriedSubscriptionCools(t *testing.T) {
	quota := &Error{HTTPStatus: http.StatusTooManyRequests, Message: `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached"}}`}
	for _, operation := range []string{"execute", "stream", "count"} {
		t.Run(operation, func(t *testing.T) {
			m, executor, call := newHubFallbackTest(t, operation, "codex", 3, "sub", "paid")
			executor.failures["sub"] = []error{io.EOF, quota}
			start := time.Now()
			if err := call(); err != nil {
				t.Fatal(err)
			}
			assertHubAuthCalls(t, executor, "sub", "sub", "paid")
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("request waited %v for a cooling subscription", elapsed)
			}
			if bound, _ := m.LookupSessionAffinity("codex", executor.model, hubFallbackSessionID); bound != nil && bound.ID == executor.authIDs["paid"] {
				t.Fatal("session bound to the paid key")
			}
		})
	}
}

// P2-b: a provider alias gets the same subscription retry as its canonical name.
func TestHubProviderAliasRetriesSubscription(t *testing.T) {
	for _, operation := range []string{"execute", "stream", "count"} {
		t.Run(operation, func(t *testing.T) {
			_, executor, call := newHubFallbackTest(t, operation, "kimi", 1, "sub", "paid")
			executor.providers = []string{"kimi.com"}
			executor.failures["sub"] = []error{io.EOF}
			if err := call(); err != nil {
				t.Fatal(err)
			}
			assertHubAuthCalls(t, executor, "sub", "sub")
		})
	}
}

// P2-c: only a PROTOCOL_ERROR reset sent by the peer is transient. A stream
// error the local transport raised for a malformed response is not.
func TestHubLocalHTTP2ProtocolErrorNotTransient(t *testing.T) {
	post := func(err error) error {
		return &url.Error{Op: "Post", URL: "https://chatgpt.com/backend-api/codex/responses", Err: err}
	}
	local := map[string]error{
		"headers after end stream": post(http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol, Cause: errors.New("protocol error: headers after END_STREAM")}),
		"data before headers":      post(http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol}),
		"text":                     post(errors.New(`stream error: stream ID 3; PROTOCOL_ERROR; invalid header field value for "x-test"`)),
	}
	peer := map[string]error{
		"typed": post(http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol, Cause: errors.New("received from peer")}),
		"text":  post(errors.New("stream error: stream ID 1; PROTOCOL_ERROR; received from peer")),
	}
	for name, err := range local {
		if isTransientTransportError(err) {
			t.Errorf("local %s: classified as transient: %v", name, err)
		}
	}
	for name, err := range peer {
		if !isTransientTransportError(err) {
			t.Errorf("peer %s: not classified as transient: %v", name, err)
		}
	}
	for _, operation := range []string{"execute", "stream", "count"} {
		t.Run(operation, func(t *testing.T) {
			_, executor, call := newHubFallbackTest(t, operation, "codex", 1, "sub", "paid")
			executor.failures["sub"] = []error{local["headers after end stream"]}
			_ = call()
			if len(executor.calls) < 2 || executor.calls[1] != "paid" {
				t.Fatalf("credential calls = %v, want the paid key right after the local protocol failure", executor.calls)
			}
		})
	}
}

type namedHubExecutor struct {
	*hubFallbackTestExecutor
	provider string
}

func (e namedHubExecutor) Identifier() string { return e.provider }

// P2-a: on a route with API keys only, a priority -1 key is not a paid
// fallback, so a healthy binding to it survives a ready priority 0 key.
func TestHubAPIKeyOnlyRouteKeepsAffinity(t *testing.T) {
	for _, operation := range []string{"execute", "stream", "count"} {
		t.Run(operation, func(t *testing.T) {
			selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &RemainingPerDaySelector{}, TTL: time.Hour})
			t.Cleanup(selector.Stop)
			m := NewManager(nil, selector, nil)
			m.SetRetryConfig(0, 30*time.Second, 1)
			e := &hubFallbackTestExecutor{
				model: "hub-model-" + t.Name(), authIDs: make(map[string]string), names: make(map[string]string),
				failures: make(map[string][]error), midStream: make(map[string][]error),
			}
			var providers []string
			for name, priority := range map[string]string{"primary": "0", "fallback": "-1"} {
				provider := "openai-compatible-" + name
				providers = append(providers, provider)
				m.RegisterExecutor(namedHubExecutor{e, provider})
				id := t.Name() + "/" + name
				e.authIDs[name], e.names[id] = id, name
				registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: e.model}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
				attributes := map[string]string{"priority": priority, "auth_kind": "apikey", "api_key": "test-key", "compat_name": name}
				if _, err := m.Register(context.Background(), &Auth{ID: id, Provider: "openai-compatibility", Label: name, Attributes: attributes}); err != nil {
					t.Fatal(err)
				}
			}
			e.failures["primary"] = []error{&Error{HTTPStatus: http.StatusServiceUnavailable, Message: "upstream unavailable"}}
			bindHubSession(m, e, "fallback")

			req := cliproxyexecutor.Request{Model: e.model}
			opts := cliproxyexecutor.Options{Headers: hubSessionHeaders("")}
			var err error
			switch operation {
			case "stream":
				var result *cliproxyexecutor.StreamResult
				if result, err = m.ExecuteStream(context.Background(), providers, req, opts); err == nil {
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							err = chunk.Err
						}
					}
				}
			case "count":
				_, err = m.ExecuteCount(context.Background(), providers, req, opts)
			default:
				_, err = m.Execute(context.Background(), providers, req, opts)
			}
			if err != nil {
				t.Fatalf("request failed: %v (calls %v)", err, e.calls)
			}
			assertHubAuthCalls(t, e, "fallback")
		})
	}
}

// P1-c: a fresh Codex WebSocket turn takes a ready HTTP-only subscription over
// a WebSocket-capable paid key.
func TestSchedulerPick_CodexWebsocketKeepsSubscriptionBeforePaid(t *testing.T) {
	scheduler := newSchedulerForTest(
		&RoundRobinSelector{},
		&Auth{ID: "codex-oauth", Provider: "codex", Attributes: map[string]string{"priority": "0", "auth_kind": "oauth"}},
		&Auth{ID: "codex-oauth-ws", Provider: "codex", Attributes: map[string]string{"priority": "-1", "auth_kind": "oauth", "websockets": "true"}},
		&Auth{ID: "codex-paid-ws", Provider: "codex", Attributes: map[string]string{"priority": "-1", "auth_kind": "apikey", "api_key": "test-key", "websockets": "true"}},
	)
	ctx := cliproxyexecutor.WithDownstreamWebsocket(context.Background())
	tried := map[string]struct{}{"codex-oauth-ws": {}}
	for index := 0; index < 3; index++ {
		got, err := scheduler.pickSingle(ctx, "codex", "", cliproxyexecutor.Options{}, tried)
		if err != nil {
			t.Fatalf("pick without the WebSocket subscription #%d: %v", index, err)
		}
		if got.ID != "codex-oauth" {
			t.Fatalf("pick without the WebSocket subscription #%d = %s, want the HTTP-only subscription", index, got.ID)
		}
	}
	for index := 0; index < 3; index++ {
		got, err := scheduler.pickSingle(ctx, "codex", "", cliproxyexecutor.Options{}, nil)
		if err != nil {
			t.Fatalf("pick #%d: %v", index, err)
		}
		// A WebSocket-capable subscription still outranks an HTTP-only one.
		if got.ID != "codex-oauth-ws" {
			t.Fatalf("pick #%d = %s, want the WebSocket-capable subscription", index, got.ID)
		}
	}
	tried["codex-oauth"] = struct{}{}
	if got, err := scheduler.pickSingle(ctx, "codex", "", cliproxyexecutor.Options{}, tried); err != nil || got.ID != "codex-paid-ws" {
		t.Fatalf("pick with every subscription tried = %v, %v; want the paid key", got, err)
	}
}
