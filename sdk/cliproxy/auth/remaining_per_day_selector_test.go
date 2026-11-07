package auth

import (
	"math"
	"testing"
	"time"
)

func TestRemainingPerDayScore(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	win := func(days, used float64) quotaResetWindows {
		return quotaResetWindows{long: quotaWindowReset{at: now.Add(time.Duration(days * 24 * float64(time.Hour))), observedAt: now, used: used, usedKnown: true}}
	}
	soon := remainingPerDayScore(win(1, 0.6), now)   // 0.4/day
	later := remainingPerDayScore(win(6, 0.05), now) // ~0.158/day
	if !(soon > later) {
		t.Fatalf("40%% left over 1 day (%v) should outrank 95%% over 6 days (%v)", soon, later)
	}
	drained := remainingPerDayScore(win(1, 0.9), now) // 0.1/day
	if !(later > drained) {
		t.Fatalf("after burning down, the other account should win: %v vs %v", later, drained)
	}
	if !math.IsInf(remainingPerDayScore(quotaResetWindows{}, now), 1) {
		t.Fatal("unknown window should be probed first")
	}
	parked := win(1, 0.1)
	parked.short = quotaWindowReset{at: now.Add(time.Hour), observedAt: now, used: 0.99, usedKnown: true}
	if remainingPerDayScore(parked, now) >= drained {
		t.Fatal("an exhausted short window should rank last")
	}
}

func TestQuotaWindowsRecordUsage(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var w quotaResetWindows
	w.observe("claude", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Reset":       "1600000",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.6",
	}, now)
	if !w.long.usedKnown || w.long.used != 0.6 {
		t.Fatalf("claude 7d utilization not recorded: %+v", w.long)
	}
	var c quotaResetWindows
	c.observe("codex", map[string]string{
		"X-Codex-Primary-Reset-At":       "1600000",
		"X-Codex-Primary-Window-Minutes": "10080",
		"X-Codex-Primary-Used-Percent":   "9",
	}, now)
	if !c.long.usedKnown || math.Abs(c.long.used-0.09) > 1e-9 {
		t.Fatalf("codex used percent not recorded: %+v", c.long)
	}
}
