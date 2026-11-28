package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestHubStreamBillingFailureIsHiddenAndCoolsKey(t *testing.T) {
	const message = "You have no credits remaining. Add credits to continue."
	const created = `{"type":"response.created","response":{"id":"test","model":"gpt-5.5"}}`
	const delta = `{"type":"response.output_text.delta","item_id":"msg","output_index":0,"content_index":0,"delta":"hello"}`
	const compatDelta = `{"id":"test","object":"chat.completion.chunk","model":"gpt-5.5","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}`
	for _, tc := range []struct {
		name     string
		provider string
		duplex   bool
		status   string
		topLevel bool
	}{
		{name: "codex SSE without status", provider: "codex"},
		{name: "compatibility SSE without status", provider: "openai-compatibility"},
		{name: "codex duplex 429", provider: "codex", duplex: true, status: `"status_code":429,`},
		{name: "codex duplex 400", provider: "codex", duplex: true, status: `"status_code":400,`},
		{name: "codex duplex top-level error", provider: "codex", duplex: true, status: `"status_code":429,`, topLevel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const errorFields = `"code":"insufficient_quota","message":"` + message + `"`
			failed := `{"type":"response.failed","response":{"id":"test","status":"failed","error":{` + tc.status + errorFields + `}}}`
			if tc.topLevel {
				failed = `{"type":"error",` + tc.status + errorFields + `}`
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.duplex {
					conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
					if errUpgrade != nil {
						t.Error(errUpgrade)
						return
					}
					defer conn.Close()
					if _, _, errRead := conn.ReadMessage(); errRead != nil {
						t.Error(errRead)
						return
					}
					for _, frame := range []string{created, delta, failed} {
						if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(frame)); errWrite != nil {
							t.Error(errWrite)
							return
						}
					}
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				if tc.provider == "openai-compatibility" {
					fmt.Fprintf(w, "data: %s\n\ndata: %s\n\n", compatDelta, failed)
				} else {
					fmt.Fprintf(w, "data: %s\n\ndata: %s\n\ndata: %s\n\n", created, delta, failed)
				}
			}))
			defer upstream.Close()

			id := t.Name()
			const model = "gpt-5.5"
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(id, tc.provider, []*registry.ModelInfo{{ID: model}})
			defer reg.UnregisterClient(id)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager := auth.NewManager(nil, &auth.RoundRobinSelector{}, nil)
			cfg := &config.Config{}
			var executor auth.ProviderExecutor = NewCodexExecutor(cfg)
			if tc.provider == "openai-compatibility" {
				executor = NewOpenAICompatExecutor(tc.provider, cfg)
			} else if tc.duplex {
				cfg.Codex.ResponseSteering = true
				cfg.CodexResponseSteering = true
				ws := NewCodexWebsocketsExecutor(cfg)
				ws.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				executor = ws
				ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), make(chan core.WebsocketInput, 1))
			}
			manager.RegisterExecutor(executor)
			key := &auth.Auth{ID: id, Provider: tc.provider, Attributes: map[string]string{
				"api_key": "test", "base_url": upstream.URL, "priority": "-1", "websockets": "true",
			}}
			if _, errRegister := manager.Register(ctx, key); errRegister != nil {
				t.Fatal(errRegister)
			}
			opts := core.Options{
				Stream: true, SourceFormat: translator.FormatOpenAIResponse, ResponseFormat: translator.FormatOpenAIResponse,
				Metadata: map[string]any{core.ExecutionSessionMetadataKey: id},
			}
			req := core.Request{Model: model, Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`)}
			result, errStream := manager.ExecuteStream(ctx, []string{tc.provider}, req, opts)
			if errStream != nil {
				t.Fatalf("stream failed before its first payload: %v", errStream)
			}
			var terminalErr error
			var receivedDelta bool
			for chunk := range result.Chunks {
				payload := string(chunk.Payload)
				if strings.Contains(payload, message) || strings.Contains(payload, "insufficient_quota") {
					t.Errorf("stream payload exposed billing details: %s", payload)
				}
				receivedDelta = receivedDelta || strings.Contains(payload, "hello")
				if chunk.Err != nil && terminalErr == nil {
					terminalErr = chunk.Err
				}
			}
			if !receivedDelta {
				t.Error("stream did not deliver the partial response")
			}
			if status := clienterror.HTTPStatusFromError(terminalErr); status != http.StatusServiceUnavailable ||
				strings.Contains(terminalErr.Error(), message) || strings.Contains(terminalErr.Error(), "insufficient_quota") {
				t.Errorf("terminal error = %v (status %d), want a generic 503", terminalErr, status)
			}
			stored, _ := manager.GetByID(id)
			if !stored.Quota.Exceeded || stored.Quota.Reason != "credential_quota" || !stored.Quota.NextRecoverAt.After(time.Now()) {
				t.Errorf("quota = %+v, want an active credential-wide cooldown", stored.Quota)
			}
		})
	}
}
