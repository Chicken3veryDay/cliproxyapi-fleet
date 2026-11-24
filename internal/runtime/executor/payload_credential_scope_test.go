package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

			// Both Anthropic fallback groups match the single rule.
			for _, groupName := range []string{"anthropic-platform-fallback", "anthropic-platform-fallback-2"} {
				auth := byGroup[groupName]
				if auth == nil {
					t.Fatalf("missing synthesized auth for group %q", groupName)
				}
				body := runClaude(auth)
				for _, strippedPath := range []string{
					"cache_control.ttl",
					"system.0.cache_control.ttl",
					"tools.0.cache_control.ttl",
					"messages.0.content.0.cache_control.ttl",
				} {
					if ojson.GetBytes(body, strippedPath).Exists() {
						t.Fatalf("group %q: %s was not stripped: %s", groupName, strippedPath, body)
					}
				}
				// Ephemeral cache_control itself and non-1h ttl remain intact.
				if got := ojson.GetBytes(body, "system.0.cache_control.type").String(); got != "ephemeral" {
					t.Fatalf("group %q: system.0.cache_control.type = %q, want ephemeral", groupName, got)
				}
				if got := ojson.GetBytes(body, "messages.2.content.0.cache_control.ttl").String(); got != "5m" {
					t.Fatalf("group %q: messages.2.content.0.cache_control.ttl = %q, want 5m", groupName, got)
				}
				if got := ojson.GetBytes(body, "metadata.fallback_only").String(); got != "yes" {
					t.Fatalf("group %q: metadata.fallback_only = %q, want yes", groupName, got)
				}
				if got := ojson.GetBytes(body, "metadata.unscoped_marker").String(); got != "present" {
					t.Fatalf("group %q: unscoped rule did not apply: %s", groupName, body)
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
