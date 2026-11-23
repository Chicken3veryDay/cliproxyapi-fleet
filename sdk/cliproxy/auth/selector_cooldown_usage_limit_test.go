package auth

import (
	"encoding/json"
	"testing"
	"time"
)

func cooldownErrorBody(t *testing.T, resetIn time.Duration) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(newModelCooldownError("gpt-6.2-sol", "codex", resetIn).Error()), &payload); err != nil {
		t.Fatalf("json.Unmarshal(Error()) error = %v", err)
	}
	body, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("Error() payload missing error object: %v", payload)
	}
	return body
}

// Codex only ends a turn on a 429 whose error.type is usage_limit_reached; any
// other 429 is retried after Retry-After, which for a quota cooldown is hours.
func TestModelCooldownErrorLongCooldownIsUsageLimit(t *testing.T) {
	resetIn := 47 * time.Hour
	before := time.Now()
	body := cooldownErrorBody(t, resetIn)

	if got, _ := body["type"].(string); got != "usage_limit_reached" {
		t.Fatalf("error.type = %q, want usage_limit_reached", got)
	}
	if got, _ := body["code"].(string); got != "model_cooldown" {
		t.Fatalf("error.code = %q, want model_cooldown", got)
	}
	resetsAt, ok := body["resets_at"].(float64)
	if !ok {
		t.Fatalf("error.resets_at missing: %v", body)
	}
	want := before.Add(resetIn).Unix()
	if int64(resetsAt) < want || int64(resetsAt) > want+5 {
		t.Fatalf("error.resets_at = %d, want about %d", int64(resetsAt), want)
	}
}

func TestModelCooldownErrorShortCooldownStaysRetryable(t *testing.T) {
	body := cooldownErrorBody(t, 30*time.Second)
	if _, ok := body["type"]; ok {
		t.Fatalf("error.type set for a short cooldown: %v", body["type"])
	}
	if _, ok := body["resets_at"]; ok {
		t.Fatalf("error.resets_at set for a short cooldown: %v", body["resets_at"])
	}
}
