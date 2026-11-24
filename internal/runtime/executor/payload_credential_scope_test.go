package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func synthesizeAuthsFromV8YAML(t *testing.T, raw string) (*config.Config, map[string]*cliproxyauth.Auth) {
	t.Helper()
	if err := config.ValidateV8Config([]byte(raw)); err != nil {
		t.Fatalf("ValidateV8Config failed: %v", err)
	}
	cfg, err := config.ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatalf("ParseConfigBytes failed: %v", err)
	}
	auths, err := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{
		Config:      cfg,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if err != nil {
		t.Fatalf("Synthesize failed: %v", err)
	}
	byGroup := make(map[string]*cliproxyauth.Auth, len(auths))
	for _, a := range auths {
		byGroup[a.APIKeyGroup()] = a
	}
	return cfg, byGroup
}

func TestPayloadRuleCredentialScope_AnthropicMultiGroupFilterAndIsolation(t *testing.T) {
	for _, scopeMode := range []string{"wildcard", "list"} {
		t.Run(scopeMode, func(t *testing.T) {
			var capturedClaude []byte
			claudeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read claude body: %v", err)
					return
				}
				capturedClaude = bytes.Clone(body)
				if ojson.GetBytes(body, "stream").Bool() {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-5-5\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
			}))
			defer claudeServer.Close()

			var capturedCodex []byte
			codexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read codex body: %v", err)
					return
				}
				capturedCodex = bytes.Clone(body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"))
			}))
			defer codexServer.Close()

			scopeYAML := `            api-key-group: "anthropic-platform-fallback*"`
			if scopeMode == "list" {
				scopeYAML = `            api-key-groups: ["anthropic-platform-fallback", "anthropic-platform-fallback-2"]`
			}

			raw := fmt.Sprintf(`config-version: 8
requests:
  payload:
    override:
      - models:
          - name: "*"
            protocol: "claude"
        params:
          metadata.unscoped_marker: "present"
      - models:
          - name: "*"
%s
        params:
          metadata.fallback_only: "yes"
    filter:
      - models:
          - name: "*"
            protocol: "claude"
%s
        params:
          - "cache_control.ttl"
          - 'system.#(cache_control.ttl=="1h")#.cache_control.ttl'
          - 'tools.#(cache_control.ttl=="1h")#.cache_control.ttl'
          - 'messages.#(content.#(cache_control.ttl=="1h"))#.content.#(cache_control.ttl=="1h")#.cache_control.ttl'
api-keys:
  claude:
    - name: anthropic-platform-fallback
      priority: -1
      base-url: %s
      headers:
        Authorization: Bearer ant-token-1
      keys:
        - api-key: ""
    - name: anthropic-platform-fallback-2
      priority: -1
      base-url: %s
      headers:
        Authorization: Bearer ant-token-2
      keys:
        - api-key: ""
    - name: claude-other-group
      base-url: %s
      keys:
        - api-key: sk-other-claude
  codex:
    - name: openai-platform-fallback
      priority: -1
      base-url: %s
      keys:
        - api-key: sk-openai-fallback
`, scopeYAML, scopeYAML, claudeServer.URL, claudeServer.URL, claudeServer.URL, codexServer.URL)

			cfg, byGroup := synthesizeAuthsFromV8YAML(t, raw)
			claudeExec := NewClaudeExecutor(cfg)
			codexExec := NewCodexExecutor(cfg)

			claudePayload := []byte(`{
				"model": "claude-opus-5-5",
				"max_tokens": 64,
				"cache_control": {"type": "ephemeral", "ttl": "1h"},
				"system": [
					{"type": "text", "text": "sys-1", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
				],
				"tools": [
					{"name": "t1", "description": "d1", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral", "ttl": "1h"}}
				],
				"messages": [
					{"role": "user", "content": [{"type": "text", "text": "turn-1", "cache_control": {"type": "ephemeral", "ttl": "1h"}}]},
					{"role": "assistant", "content": [{"type": "text", "text": "reply-1"}]},
					{"role": "user", "content": [{"type": "text", "text": "turn-2", "cache_control": {"type": "ephemeral", "ttl": "5m"}}]}
				]
			}`)

			runClaude := func(auth *cliproxyauth.Auth) []byte {
				t.Helper()
				capturedClaude = nil
				_, err := claudeExec.Execute(context.Background(), auth, cliproxyexecutor.Request{
					Model:   "claude-opus-5-5",
					Payload: claudePayload,
				}, cliproxyexecutor.Options{
					SourceFormat: sdktranslator.FormatClaude,
				})
				if err != nil {
					t.Fatalf("claude Execute(%s) failed: %v", auth.ID, err)
				}
				return capturedClaude
			}

			runClaudeStream := func(auth *cliproxyauth.Auth) []byte {
				t.Helper()
				capturedClaude = nil
				sr, err := claudeExec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
					Model:   "claude-opus-5-5",
					Payload: claudePayload,
				}, cliproxyexecutor.Options{
					SourceFormat: sdktranslator.FormatClaude,
					Stream:       true,
				})
				if err != nil {
					t.Fatalf("claude ExecuteStream(%s) failed: %v", auth.ID, err)
				}
				for chunk := range sr.Chunks {
					if chunk.Err != nil {
						t.Fatalf("claude ExecuteStream(%s) chunk error: %v", auth.ID, chunk.Err)
					}
				}
				return capturedClaude
			}

			// Both Anthropic fallback groups match the single rule (both Execute and ExecuteStream).
			for _, groupName := range []string{"anthropic-platform-fallback", "anthropic-platform-fallback-2"} {
				auth := byGroup[groupName]
				if auth == nil {
					t.Fatalf("missing synthesized auth for group %q", groupName)
				}
				for _, pathName := range []string{"execute", "stream"} {
					var body []byte
					if pathName == "execute" {
						body = runClaude(auth)
					} else {
						body = runClaudeStream(auth)
					}
					for _, strippedPath := range []string{
						"cache_control.ttl",
						"system.0.cache_control.ttl",
						"tools.0.cache_control.ttl",
						"messages.0.content.0.cache_control.ttl",
					} {
						if ojson.GetBytes(body, strippedPath).Exists() {
							t.Fatalf("group %q (%s): %s was not stripped: %s", groupName, pathName, strippedPath, body)
						}
					}
					// Ephemeral cache_control itself and non-1h ttl remain intact.
					if got := ojson.GetBytes(body, "system.0.cache_control.type").String(); got != "ephemeral" {
						t.Fatalf("group %q (%s): system.0.cache_control.type = %q, want ephemeral", groupName, pathName, got)
					}
					if got := ojson.GetBytes(body, "messages.2.content.0.cache_control.ttl").String(); got != "5m" {
						t.Fatalf("group %q (%s): messages.2.content.0.cache_control.ttl = %q, want 5m", groupName, pathName, got)
					}
					if got := ojson.GetBytes(body, "metadata.fallback_only").String(); got != "yes" {
						t.Fatalf("group %q (%s): metadata.fallback_only = %q, want yes", groupName, pathName, got)
					}
					if got := ojson.GetBytes(body, "metadata.unscoped_marker").String(); got != "present" {
						t.Fatalf("group %q (%s): unscoped rule did not apply: %s", groupName, pathName, body)
					}
				}
			}

			// Another Claude API-key group must NOT match the scoped rules, but still gets the unscoped rule.
			otherBody := runClaude(byGroup["claude-other-group"])
			for _, keptPath := range []string{
				"cache_control.ttl",
				"system.0.cache_control.ttl",
				"tools.0.cache_control.ttl",
				"messages.0.content.0.cache_control.ttl",
			} {
				if got := ojson.GetBytes(otherBody, keptPath).String(); got != "1h" {
					t.Fatalf("claude-other-group: %s = %q, want 1h (body=%s)", keptPath, got, otherBody)
				}
			}
			if ojson.GetBytes(otherBody, "metadata.fallback_only").Exists() {
				t.Fatalf("claude-other-group unexpectedly matched fallback rule: %s", otherBody)
			}
			if got := ojson.GetBytes(otherBody, "metadata.unscoped_marker").String(); got != "present" {
				t.Fatalf("claude-other-group missed unscoped rule: %s", otherBody)
			}

			// Claude OAuth auth must NOT match the scoped rules, even if an unscoped rule still applies.
			oauthAuth := &cliproxyauth.Auth{
				ID:       "claude-oauth-sub",
				Provider: "claude",
				Attributes: map[string]string{
					"base_url": claudeServer.URL,
				},
				Metadata: map[string]any{
					"access_token": "oauth-access-token",
				},
			}
			oauthBody := runClaude(oauthAuth)
			for _, keptPath := range []string{
				"cache_control.ttl",
				"system.0.cache_control.ttl",
				"tools.0.cache_control.ttl",
				"messages.0.content.0.cache_control.ttl",
			} {
				if got := ojson.GetBytes(oauthBody, keptPath).String(); got != "1h" {
					t.Fatalf("claude OAuth: %s = %q, want 1h (body=%s)", keptPath, got, oauthBody)
				}
			}
			if ojson.GetBytes(oauthBody, "metadata.fallback_only").Exists() {
				t.Fatalf("claude OAuth unexpectedly matched fallback rule: %s", oauthBody)
			}
			if got := ojson.GetBytes(oauthBody, "metadata.unscoped_marker").String(); got != "present" {
				t.Fatalf("claude OAuth missed unscoped rule: %s", oauthBody)
			}

			// Codex fallback group must NOT match the Anthropic-scoped rule (even the one without protocol restriction).
			codexAuth := byGroup["openai-platform-fallback"]
			if codexAuth == nil {
				t.Fatal("missing synthesized auth for openai-platform-fallback")
			}
			capturedCodex = nil
			_, err := codexExec.Execute(context.Background(), codexAuth, cliproxyexecutor.Request{
				Model:   "gpt-6.2-sol",
				Payload: []byte(`{"model":"gpt-6.2-sol","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`),
			}, cliproxyexecutor.Options{
				SourceFormat: sdktranslator.FormatOpenAIResponse,
			})
			if err != nil {
				t.Fatalf("codex Execute failed: %v", err)
			}
			if ojson.GetBytes(capturedCodex, "metadata.fallback_only").Exists() {
				t.Fatalf("openai-platform-fallback unexpectedly matched Anthropic fallback rule: %s", capturedCodex)
			}
		})
	}
}

func TestPayloadRuleCredentialScope_ByCredentialID(t *testing.T) {
	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{
				{
					Models: []config.PayloadModelRule{{
						Name:        "*",
						Protocol:    "claude",
						Credentials: []string{"cred-alpha", "cred-beta-*"},
					}},
					Params: map[string]any{"metadata.scoped_cred": "matched"},
				},
			},
		},
	}
	exec := NewClaudeExecutor(cfg)
	req := cliproxyexecutor.Request{
		Model:   "claude-opus-5-5",
		Payload: []byte(`{"model":"claude-opus-5-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`),
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude}

	for _, tc := range []struct {
		id        string
		wantMatch bool
	}{
		{id: "cred-alpha", wantMatch: true},
		{id: "cred-beta-2", wantMatch: true},
		{id: "cred-gamma", wantMatch: false},
	} {
		captured = nil
		auth := &cliproxyauth.Auth{
			ID:         tc.id,
			Provider:   "claude",
			Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL},
		}
		if _, err := exec.Execute(context.Background(), auth, req, opts); err != nil {
			t.Fatalf("Execute(%s) error: %v", tc.id, err)
		}
		got := ojson.GetBytes(captured, "metadata.scoped_cred").String() == "matched"
		if got != tc.wantMatch {
			t.Fatalf("credential %q matched=%v, want %v; body=%s", tc.id, got, tc.wantMatch, captured)
		}
	}
}

func TestCodexPromptCacheRetention_OpenAIPlatformFallbackKeepsConfiguredRetentionAndCacheKey(t *testing.T) {
	raw := `config-version: 8
requests:
  payload:
    override:
      - models:
          - name: "gpt-5.4"
            protocol: "codex"
            api-key-group: "openai-platform-fallback"
        params:
          prompt_cache_retention: "24h"
      - models:
          - name: "gpt-6.2-*"
            protocol: "codex"
            api-key-group: "openai-platform-fallback"
        params:
          prompt_cache_options.ttl: "30m"
api-keys:
  codex:
    - name: openai-platform-fallback
      priority: -1
      base-url: https://api.openai.com/v1
      keys:
        - api-key: sk-openai-platform
          disable-codex-cloaking: true
`
	cfg, byGroup := synthesizeAuthsFromV8YAML(t, raw)
	auth := byGroup["openai-platform-fallback"]
	if auth == nil {
		t.Fatal("missing synthesized auth for openai-platform-fallback")
	}

	var capturedURL string
	var capturedBody []byte
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		capturedURL = req.URL.String()
		capturedBody = bytes.Clone(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_oai\",\"status\":\"completed\",\"model\":\"gpt-5.4\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")),
			Request:    req,
		}, nil
	})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", rt)
	exec := NewCodexExecutor(cfg)

	reqLegacy := cliproxyexecutor.Request{
		Model:   "gpt-5.4",
		Payload: []byte(`{"model":"gpt-5.4","prompt_cache_key":"sess-client-key","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`),
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}

	// Execute path
	if _, err := exec.Execute(ctx, auth, reqLegacy, opts); err != nil {
		t.Fatalf("Execute(gpt-5.4) error: %v", err)
	}
	if capturedURL != "https://api.openai.com/v1/responses" {
		t.Fatalf("Execute URL = %q, want https://api.openai.com/v1/responses", capturedURL)
	}
	if got := ojson.GetBytes(capturedBody, "prompt_cache_retention").String(); got != "24h" {
		t.Fatalf("Execute prompt_cache_retention = %q, want 24h; body=%s", got, capturedBody)
	}
	if got := ojson.GetBytes(capturedBody, "prompt_cache_key").String(); got != "sess-client-key" {
		t.Fatalf("Execute prompt_cache_key = %q, want sess-client-key; body=%s", got, capturedBody)
	}

	// ExecuteStream path
	capturedBody = nil
	sr, err := exec.ExecuteStream(ctx, auth, reqLegacy, opts)
	if err != nil {
		t.Fatalf("ExecuteStream(gpt-5.4) error: %v", err)
	}
	for chunk := range sr.Chunks {
		if chunk.Err != nil {
			t.Fatalf("ExecuteStream chunk error: %v", chunk.Err)
		}
	}
	if got := ojson.GetBytes(capturedBody, "prompt_cache_retention").String(); got != "24h" {
		t.Fatalf("ExecuteStream prompt_cache_retention = %q, want 24h; body=%s", got, capturedBody)
	}
	if got := ojson.GetBytes(capturedBody, "prompt_cache_key").String(); got != "sess-client-key" {
		t.Fatalf("ExecuteStream prompt_cache_key = %q, want sess-client-key; body=%s", got, capturedBody)
	}

	// GPT-6.2 path using prompt_cache_options.ttl
	capturedBody = nil
	reqModern := cliproxyexecutor.Request{
		Model:   "gpt-6.2-sol",
		Payload: []byte(`{"model":"gpt-6.2-sol","prompt_cache_key":"sess-gpt62","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`),
	}
	if _, err := exec.Execute(ctx, auth, reqModern, opts); err != nil {
		t.Fatalf("Execute(gpt-6.2-sol) error: %v", err)
	}
	if got := ojson.GetBytes(capturedBody, "prompt_cache_options.ttl").String(); got != "30m" {
		t.Fatalf("Execute(gpt-6.2-sol) prompt_cache_options.ttl = %q, want 30m; body=%s", got, capturedBody)
	}
	if got := ojson.GetBytes(capturedBody, "prompt_cache_key").String(); got != "sess-gpt62" {
		t.Fatalf("Execute(gpt-6.2-sol) prompt_cache_key = %q, want sess-gpt62; body=%s", got, capturedBody)
	}

	// WebSocket prepare path
	wsExec := NewCodexWebsocketsExecutor(cfg)
	preparedWS, err := wsExec.prepareCodexWebsocketStream(context.Background(), auth, reqLegacy, opts)
	if err != nil {
		t.Fatalf("prepareCodexWebsocketStream error: %v", err)
	}
	if got := ojson.GetBytes(preparedWS.clientBody, "prompt_cache_retention").String(); got != "24h" {
		t.Fatalf("WebSocket prompt_cache_retention = %q, want 24h; body=%s", got, preparedWS.clientBody)
	}
	if got := ojson.GetBytes(preparedWS.clientBody, "prompt_cache_key").String(); got != "sess-client-key" {
		t.Fatalf("WebSocket prompt_cache_key = %q, want sess-client-key; body=%s", got, preparedWS.clientBody)
	}

	// FormatCodex path without override must not strip prompt_cache_retention on non-ChatGPT API-key auth.
	capturedBody = nil
	emptyExec := NewCodexExecutor(&config.Config{})
	reqNative := cliproxyexecutor.Request{
		Model:   "gpt-5.4",
		Payload: []byte(`{"model":"gpt-5.4","prompt_cache_retention":"24h","prompt_cache_key":"sess-native","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`),
	}
	if _, err := emptyExec.Execute(ctx, auth, reqNative, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatCodex}); err != nil {
		t.Fatalf("Execute(FormatCodex) error: %v", err)
	}
	if got := ojson.GetBytes(capturedBody, "prompt_cache_retention").String(); got != "24h" {
		t.Fatalf("FormatCodex on api.openai.com dropped prompt_cache_retention: %s", capturedBody)
	}
}

func TestCodexPromptCacheRetention_ChatGPTBackendAndOAuthStillStripField(t *testing.T) {
	// Even an unscoped override setting prompt_cache_retention must never reach ChatGPT-backend or OAuth paths.
	cfg := &config.Config{
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "*", Protocol: "codex"}},
				Params: map[string]any{"prompt_cache_retention": "24h"},
			}},
		},
	}

	var capturedURL string
	var capturedBody []byte
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		capturedURL = req.URL.String()
		capturedBody = bytes.Clone(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_cgpt\",\"status\":\"completed\",\"model\":\"gpt-5.4\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")),
			Request:    req,
		}, nil
	})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", rt)
	exec := NewCodexExecutor(cfg)
	wsExec := NewCodexWebsocketsExecutor(cfg)

	req := cliproxyexecutor.Request{
		Model:   "gpt-5.4",
		Payload: []byte(`{"model":"gpt-5.4","prompt_cache_retention":"24h","prompt_cache_key":"sess-oauth","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`),
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}

	cases := []struct {
		name      string
		auth      *cliproxyauth.Auth
		wantURL   string
		wantKept  bool
		skipCheck bool
	}{
		{
			name: "chatgpt-oauth-default-url",
			auth: &cliproxyauth.Auth{
				ID:       "codex-oauth-1",
				Provider: "codex",
				Metadata: map[string]any{"access_token": "oauth-tok"},
			},
			wantURL:  "https://chatgpt.com/backend-api/codex/responses",
			wantKept: false,
		},
		{
			name: "chatgpt-apikey-explicit-url",
			auth: &cliproxyauth.Auth{
				ID:         "codex-chatgpt-apikey",
				Provider:   "codex",
				Attributes: map[string]string{"api_key": "sk-chatgpt", "base_url": "https://chatgpt.com/backend-api/codex"},
			},
			wantURL:  "https://chatgpt.com/backend-api/codex/responses",
			wantKept: false,
		},
		{
			name: "siwc-oauth-openai-url",
			auth: &cliproxyauth.Auth{
				ID:       "codex-siwc-oauth",
				Provider: "codex",
				Metadata: map[string]any{
					"use_siwc": true,
					"siwc": map[string]any{
						"access_token": "siwc-tok",
						"client_id":    "oaiapp_test",
					},
				},
			},
			wantURL:  "https://api.openai.com/v1/responses",
			wantKept: false,
		},
		{
			name: "openai-platform-apikey",
			auth: &cliproxyauth.Auth{
				ID:         "codex-openai-apikey",
				Provider:   "codex",
				Attributes: map[string]string{"api_key": "sk-openai", "base_url": "https://api.openai.com/v1"},
			},
			wantURL:  "https://api.openai.com/v1/responses",
			wantKept: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			capturedBody = nil
			capturedURL = ""
			if _, err := exec.Execute(ctx, tc.auth, req, opts); err != nil {
				t.Fatalf("Execute error: %v", err)
			}
			if capturedURL != tc.wantURL {
				t.Fatalf("Execute URL = %q, want %q", capturedURL, tc.wantURL)
			}
			gotExec := ojson.GetBytes(capturedBody, "prompt_cache_retention").Exists()
			if gotExec != tc.wantKept {
				t.Fatalf("Execute prompt_cache_retention exists=%v, want %v; body=%s", gotExec, tc.wantKept, capturedBody)
			}

			// ExecuteStream
			capturedBody = nil
			sr, err := exec.ExecuteStream(ctx, tc.auth, req, opts)
			if err != nil {
				t.Fatalf("ExecuteStream error: %v", err)
			}
			for chunk := range sr.Chunks {
				if chunk.Err != nil {
					t.Fatalf("ExecuteStream chunk error: %v", chunk.Err)
				}
			}
			gotStream := ojson.GetBytes(capturedBody, "prompt_cache_retention").Exists()
			if gotStream != tc.wantKept {
				t.Fatalf("ExecuteStream prompt_cache_retention exists=%v, want %v; body=%s", gotStream, tc.wantKept, capturedBody)
			}

			// WebSocket prepare
			preparedWS, err := wsExec.prepareCodexWebsocketStream(context.Background(), tc.auth, req, opts)
			if err != nil {
				t.Fatalf("prepareCodexWebsocketStream error: %v", err)
			}
			gotWS := ojson.GetBytes(preparedWS.clientBody, "prompt_cache_retention").Exists()
			if gotWS != tc.wantKept {
				t.Fatalf("WebSocket prompt_cache_retention exists=%v, want %v; body=%s", gotWS, tc.wantKept, preparedWS.clientBody)
			}
		})
	}
}
