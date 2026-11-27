package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"golang.org/x/net/http2"
)

func TestHubUnrelatedRouteCannotDeferPaidKey(t *testing.T) {
	ctx := context.Background()
	m, e, call := newHubFallbackTest(t, "execute", "codex", 3, "sub", "paid")
	m.RegisterExecutor(namedHubExecutor{e, "openai-compatible-extra"})
	id := t.Name() + "/extra"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(id, "openai-compatible-extra", []*registry.ModelInfo{{ID: e.model}})
	defer reg.UnregisterClient(id)
	e.names[id] = "extra"
	extra := &Auth{ID: id, Provider: "openai-compatibility", Label: "extra", Attributes: map[string]string{"auth_kind": "apikey", "priority": "-1", "compat_name": "extra"}}
	if _, err := m.Register(ctx, extra); err != nil {
		t.Fatal(err)
	}
	e.providers = []string{"codex", "openai-compatible-extra"}
	quota := &Error{HTTPStatus: http.StatusTooManyRequests, Message: `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached"}}`}
	e.failures["sub"] = []error{io.EOF, quota}
	e.failures["extra"] = []error{io.EOF, io.EOF, io.EOF, io.EOF}
	if err := call(); err != nil {
		t.Fatal(err)
	}
	// Affinity can select either route first in the second round.
	if len(e.calls) == 5 && e.calls[2] == "extra" {
		assertHubAuthCalls(t, e, "sub", "extra", "extra", "sub", "paid")
	} else {
		assertHubAuthCalls(t, e, "sub", "extra", "sub", "extra", "paid")
	}
}

func TestHubDeferredPaidKeyKeepsItsRetry(t *testing.T) {
	for _, operation := range []string{"execute", "count", "stream"} {
		t.Run(operation, func(t *testing.T) {
			for _, paidRecovers := range []bool{true, false} {
				name := "retries once and succeeds"
				if !paidRecovers {
					name = "stops after the one retry fails"
				}
				t.Run(name, func(t *testing.T) {
					m, e, call := newHubFallbackTest(t, operation, "codex", 3, "sub", "paid")
					m.SetRetryConfig(3, 0, 0)
					paid, _ := m.GetByID(e.authIDs["paid"])
					paid.Metadata["request_retry"] = 1
					if _, errUpdate := m.Update(context.Background(), paid); errUpdate != nil {
						t.Fatal(errUpdate)
					}
					quota := &Error{HTTPStatus: http.StatusTooManyRequests, Message: `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached"}}`}
					e.failures["sub"] = []error{io.EOF, quota}
					e.failures["paid"] = []error{io.EOF}
					if !paidRecovers {
						e.failures["paid"] = append(e.failures["paid"], io.EOF)
					}
					if err := call(); paidRecovers && err != nil || !paidRecovers && !errors.Is(err, io.EOF) {
						t.Errorf("request error = %v, want successful paid retry = %v", err, paidRecovers)
					}
					assertHubAuthCalls(t, e, "sub", "sub", "paid", "paid")
				})
			}
		})
	}
}

func TestHubUnknownFileKindKeepsPaidAffinity(t *testing.T) {
	m, e, call := newHubFallbackTest(t, "execute", "codex", 0, "paid")
	ctx := context.Background()
	id := t.Name() + "/unclassified"
	a := &Auth{ID: id, Provider: "codex", FileName: "legacy.json"}
	if a.AuthKind() != "" {
		t.Fatalf("setup kind = %q", a.AuthKind())
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(id, "codex", []*registry.ModelInfo{{ID: e.model}})
	defer reg.UnregisterClient(id)
	e.names[id] = "unclassified"
	if _, err := m.Register(ctx, a); err != nil {
		t.Fatal(err)
	}
	bindHubSession(m, e, "paid")
	if err := call(); err != nil {
		t.Fatal(err)
	}
	assertHubAuthCalls(t, e, "paid")
}

func TestHubOnlyExactPeerHTTP2ResetIsTransient(t *testing.T) {
	const protocolError = "stream error: stream ID 1; PROTOCOL_ERROR; "
	const localCause = `invalid header field name "unexpected EOF"`
	for _, tc := range []struct {
		name          string
		err           error
		wantTransient bool
	}{
		{"typed local diagnostic containing EOF", http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol, Cause: errors.New(localCause)}, false},
		{"local diagnostic containing EOF", errors.New(protocolError + localCause), false},
		{"local diagnostic starting with peer marker", errors.New(protocolError + "received from peer (invalid response)"), false},
		{"wrapped peer reset", errors.New(protocolError + "received from peer"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := resultErrorFromError(&url.Error{Op: "Post", URL: "https://upstream.invalid/responses", Err: tc.err})
			if got := isTransientTransportResultError(result); got != tc.wantTransient {
				t.Errorf("transient = %v, want %v for %v", got, tc.wantTransient, result)
			}
			if got := shouldSkipCredentialCooldown(result); got != tc.wantTransient {
				t.Errorf("skip credential cooldown = %v, want %v for %v", got, tc.wantTransient, result)
			}
		})
	}
}
