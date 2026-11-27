package auth

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const hubFallbackSessionID = "fleet-test-session"

func TestHubSubscriptionBeforePaid(t *testing.T) {
	tlsFailure := &url.Error{
		Op: "Post", URL: "https://example.invalid/v1/messages",
		Err: fmt.Errorf("claude tls: handshake upstream: %w", &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}),
	}
	anthropicBilling := &Error{HTTPStatus: http.StatusBadRequest, Message: `{"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low to access the Anthropic API."}}`}
	openAIBilling := &Error{HTTPStatus: http.StatusTooManyRequests, Message: `{"error":{"code":"insufficient_quota","type":"insufficient_quota","message":"Check your plan and billing details."}}`}
	for _, operation := range []string{"execute", "stream", "count"} {
		t.Run(operation, func(t *testing.T) {
			t.Run("retry subscription", func(t *testing.T) {
				m, executor, call := newHubFallbackTest(t, operation, "claude", 1, "sub", "paid")
				executor.failures["sub"] = []error{fakeClaudeFastTransportError{tlsFailure}}
				executor.failures["paid"] = []error{anthropicBilling}
				if err := call(); err != nil {
					t.Fatal(err)
				}
				assertHubAuthCalls(t, executor, "sub", "sub")
				assertNoCooldown(t, m, executor.authIDs["sub"], executor.model)
			})
			t.Run("exhaust budget then recover affinity", func(t *testing.T) {
				m, executor, call := newHubFallbackTest(t, operation, "claude", 2, "sub", "paid")
				executor.failures["sub"] = []error{tlsFailure, io.EOF, tlsFailure}
				if err := call(); err != nil {
					t.Fatal(err)
				}
				assertHubAuthCalls(t, executor, "sub", "sub", "sub", "paid")
				if bound, state := m.LookupSessionAffinity("claude", executor.model, hubFallbackSessionID); bound == nil || bound.ID != executor.authIDs["sub"] {
					t.Fatalf("affinity after temporary fallback = %v, want subscription (%s)", state, executor.authIDs["sub"])
				}
				if err := call(); err != nil {
					t.Fatal(err)
				}
				assertHubAuthCalls(t, executor, "sub", "sub", "sub", "paid", "sub")
				assertNoCooldown(t, m, executor.authIDs["sub"], executor.model)
			})
			t.Run("override a cached paid binding", func(t *testing.T) {
				m, executor, call := newHubFallbackTest(t, operation, "claude", 0, "sub", "paid")
				selector := m.Selector().(*SessionAffinitySelector)
				selector.cache.SetAliases(executor.authIDs["paid"], "mixed::claude:"+hubFallbackSessionID+"::"+canonicalModelKey(executor.model))
				if err := call(); err != nil {
					t.Fatal(err)
				}
				assertHubAuthCalls(t, executor, "sub")
			})
			t.Run("try peer before retrying", func(t *testing.T) {
				_, executor, call := newHubFallbackTest(t, operation, "claude", 1, "sub", "sub-peer", "paid")
				executor.failures["sub"] = []error{tlsFailure}
				if err := call(); err != nil {
					t.Fatal(err)
				}
				assertHubAuthCalls(t, executor, "sub", "sub-peer")
			})
			t.Run("preserve subscription error", func(t *testing.T) {
				_, executor, call := newHubFallbackTest(t, operation, "claude", 1, "sub", "paid")
				executor.failures["sub"] = []error{tlsFailure, tlsFailure}
				executor.failures["paid"] = []error{anthropicBilling}
				if err := call(); err != tlsFailure {
					t.Fatalf("terminal error = %v, want subscription error", err)
				}
				assertHubAuthCalls(t, executor, "sub", "sub", "paid")
			})
			for _, tc := range []struct {
				name     string
				provider string
				billing  error
			}{
				{"anthropic", "claude", anthropicBilling},
				{"anthropic fast direct response", "claude", newFastDirectResponseTestError(anthropicBilling.HTTPStatus, anthropicBilling.Message)},
				{"openai", "openai-compatibility", openAIBilling},
			} {
				t.Run(tc.name+"/billing quota", func(t *testing.T) {
					m, executor, call := newHubFallbackTest(t, operation, tc.provider, 0, "paid", "paid-second")
					executor.failures["paid"] = []error{tc.billing}
					executor.failures["paid-second"] = []error{tc.billing}
					if err := call(); statusCodeFromError(err) != http.StatusServiceUnavailable || strings.Contains(err.Error(), tc.billing.Error()) {
						t.Fatalf("terminal error = %v, want a sanitized 503", err)
					}
					assertHubAuthCalls(t, executor, "paid", "paid-second")
					if err := call(); statusCodeFromError(err) != http.StatusTooManyRequests || strings.Contains(err.Error(), "last_upstream_error") {
						t.Fatalf("error with both keys cooling = %v, want a sanitized 429", err)
					}
					assertHubAuthCalls(t, executor, "paid", "paid-second")
					for _, name := range []string{"paid", "paid-second"} {
						credential, _ := m.GetByID(executor.authIDs[name])
						if !credential.Quota.Exceeded || credential.Quota.Reason != "credential_quota" || time.Until(credential.Quota.NextRecoverAt) < 59*time.Minute {
							t.Fatalf("%s credential-wide quota = %+v", name, credential.Quota)
						}
						if blocked, _, _ := isAuthBlockedForModel(credential, "another-model", time.Now()); !blocked {
							t.Fatalf("%s billing cooldown did not cover another model", name)
						}
					}
				})
			}
		})
	}
}

type fakeClaudeFastTransportError struct{ error }

func (e fakeClaudeFastTransportError) IsRequestScoped() bool        { return true }
func (e fakeClaudeFastTransportError) PreHTTPTransportError() error { return e.error }

type hubFallbackTestExecutor struct {
	authFallbackExecutor
	model    string
	authIDs  map[string]string
	names    map[string]string
	failures map[string][]error
	calls    []string
}

func (e *hubFallbackTestExecutor) next(ctx context.Context, auth *Auth) error {
	cliproxyexecutor.MarkUpstreamAttempt(ctx)
	name := e.names[auth.ID]
	e.calls = append(e.calls, name)
	queue := e.failures[name]
	if len(queue) == 0 {
		return nil
	}
	e.failures[name] = queue[1:]
	return queue[0]
}

func (e *hubFallbackTestExecutor) Execute(ctx context.Context, a *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{Payload: []byte("ok")}, e.next(ctx, a)
}

func (e *hubFallbackTestExecutor) CountTokens(ctx context.Context, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, a, req, opts)
}

func (e *hubFallbackTestExecutor) ExecuteStream(ctx context.Context, a *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if err := e.next(ctx, a); err != nil {
		return nil, err
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("ok")}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func newHubFallbackTest(t *testing.T, operation, provider string, retries int, names ...string) (*Manager, *hubFallbackTestExecutor, func() error) {
	t.Helper()
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &RemainingPerDaySelector{}, TTL: time.Hour})
	t.Cleanup(selector.Stop)
	m := NewManager(nil, selector, nil)
	m.SetRetryConfig(retries, 30*time.Second, 0)
	e := &hubFallbackTestExecutor{
		authFallbackExecutor: authFallbackExecutor{id: provider},
		model:                "hub-model-" + t.Name(), authIDs: make(map[string]string), names: make(map[string]string),
		failures: make(map[string][]error),
	}
	m.RegisterExecutor(e)
	ctx := context.Background()
	for _, name := range names {
		id := t.Name() + "/" + name
		e.authIDs[name], e.names[id] = id, name
		attributes := map[string]string{"priority": "0"}
		var metadata map[string]any
		if name == "paid" || name == "paid-second" {
			attributes["priority"] = "-1"
			attributes["auth_kind"] = "apikey"
			metadata = map[string]any{"request_retry": 0}
		}
		registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: e.model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, err := m.Register(ctx, &Auth{ID: id, Provider: provider, Attributes: attributes, Metadata: metadata}); err != nil {
			t.Fatal(err)
		}
	}
	return m, e, func() error {
		req := cliproxyexecutor.Request{Model: e.model}
		opts := cliproxyexecutor.Options{Headers: http.Header{"X-Claude-Code-Session-Id": {hubFallbackSessionID}}}
		providers := []string{provider}
		switch operation {
		case "stream":
			result, err := m.ExecuteStream(ctx, providers, req, opts)
			if err != nil {
				return err
			}
			var streamErr error
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					streamErr = chunk.Err
				}
			}
			return streamErr
		case "count":
			_, err := m.ExecuteCount(ctx, providers, req, opts)
			return err
		default:
			_, err := m.Execute(ctx, providers, req, opts)
			return err
		}
	}
}

func assertHubAuthCalls(t *testing.T, e *hubFallbackTestExecutor, want ...string) {
	t.Helper()
	if !slices.Equal(e.calls, want) {
		t.Fatalf("credential calls = %v, want %v", e.calls, want)
	}
}
