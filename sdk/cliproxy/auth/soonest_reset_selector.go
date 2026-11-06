package auth

import (
	"context"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// SoonestResetFirstSelector burns quota closest to expiry within the highest
// available priority tier. Equal reset windows use the existing round-robin ring.
// The manager uses its general selector path so every pick sees current resets.
type SoonestResetFirstSelector struct {
	roundRobin RoundRobinSelector
}

func (s *SoonestResetFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	best := available[0].Quota.resetWindows
	candidates := make([]*Auth, 0, len(available))
	for _, auth := range available {
		comparison := compareQuotaResets(auth.Quota.resetWindows, best, now)
		if comparison < 0 {
			best = auth.Quota.resetWindows
			candidates = candidates[:0]
		}
		if comparison <= 0 {
			candidates = append(candidates, auth)
		}
	}
	// Candidates retain ID order for successorIndex. Availability was already
	// checked with the request's model, including manager-resolved aliases.
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, prevalidatedAuthCandidatesKey{}, true)
	return s.roundRobin.Pick(ctx, provider, model, opts, candidates)
}

func compareQuotaResets(a, b quotaResetWindows, now time.Time) int {
	compare := func(a, b time.Time) int {
		knownA, knownB := a.After(now), b.After(now)
		// An unknown (or expired) reset sorts first: one pick teaches the hub that
		// account's window, so after a restart every account is observed once
		// instead of the first-seen account taking all traffic until its reset.
		if knownA != knownB {
			if knownA {
				return 1
			}
			return -1
		}
		if !knownA {
			return 0
		}
		return a.Compare(b)
	}
	if order := compare(a.long.at, b.long.at); order != 0 {
		return order
	}
	return compare(a.short.at, b.short.at)
}
