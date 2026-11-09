package executor

import "testing"

// Fable 5.2 reuses Fable 5.1's request shape (fallbacks, per-turn effort, preserved thinking).
func TestFable52SharesFable51RequestShape(t *testing.T) {
	for _, m := range []string{"claude-fable-5-2", "claude-fable-5-2-max"} {
		if !isClaudeFable51Model(m) || !isClaudeFable51OnlyModel(m) || !claudeModelHasPerTurnEffort(m) {
			t.Errorf("%s: want the Fable 5.1 request shape", m)
		}
	}
	if !isClaudeFable51Model("claude-fable-5.2") {
		t.Error("claude-fable-5.2: want the Fable family match")
	}
	if isClaudeFable51Model("claude-fable-5-20") {
		t.Error("claude-fable-5-20 must not match fable-5-2")
	}
}
