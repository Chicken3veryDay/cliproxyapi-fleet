package auth

import (
	"context"
	"math"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// RemainingPerDaySelector spreads load so every account's long-window quota
// runs out about when that window resets. It picks the account with the most
// remaining quota per day until its long-window reset: an account at 40% left
// resetting tomorrow outranks one at 95% left resetting in six days, and as it
// burns down the other account takes over, so traffic splits by budget/day
// instead of draining one account at a time.
//
// Accounts whose long window (reset or usage) is unknown are probed first, so
// one request teaches the hub their budget. An account whose short window is
// nearly exhausted ranks after every other. Scores within remainingPerDayTie of
// the best share the round-robin ring.
type RemainingPerDaySelector struct {
	roundRobin RoundRobinSelector
}

const (
	remainingPerDayTie       = 0.02 // relative score band treated as equal
	remainingPerDayShortFull = 0.98 // short-window usage that parks an account
	remainingPerDayMinDays   = 1.0 / 24
)

func (s *RemainingPerDaySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	scores := make([]float64, len(available))
	best := math.Inf(-1)
	for i, auth := range available {
		scores[i] = remainingPerDayScore(auth.Quota.resetWindows, now)
		best = max(best, scores[i])
	}
	candidates := make([]*Auth, 0, len(available))
	for i, auth := range available {
		if remainingPerDayNear(scores[i], best) {
			candidates = append(candidates, auth)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, prevalidatedAuthCandidatesKey{}, true)
	return s.roundRobin.Pick(ctx, provider, model, opts, candidates)
}

// remainingPerDayScore is the long window's remaining fraction per day left
// before it resets; +Inf when unknown (probe first), and negative when the
// short window is nearly used up (try last).
func remainingPerDayScore(w quotaResetWindows, now time.Time) float64 {
	if !w.long.at.After(now) || !w.long.usedKnown {
		return math.Inf(1)
	}
	days := max(w.long.at.Sub(now).Hours()/24, remainingPerDayMinDays)
	score := (1 - w.long.used) / days
	if w.short.at.After(now) && w.short.usedKnown && w.short.used >= remainingPerDayShortFull {
		score -= 1e6
	}
	return score
}

func remainingPerDayNear(score, best float64) bool {
	if math.IsInf(best, 1) {
		return math.IsInf(score, 1)
	}
	return score >= best-math.Abs(best)*remainingPerDayTie
}
