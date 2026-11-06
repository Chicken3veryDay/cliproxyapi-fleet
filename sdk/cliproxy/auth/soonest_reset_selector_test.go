package auth

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func resetAuth(id string, long, short time.Time) *Auth {
	return &Auth{ID: id, Provider: "claude", Quota: QuotaState{resetWindows: quotaResetWindows{
		long: quotaWindowReset{at: long}, short: quotaWindowReset{at: short},
	}}}
}

func TestSoonestResetFirstOrdering(t *testing.T) {
	now := time.Now()
	zero := time.Time{}
	early, late := now.Add(time.Hour), now.Add(24*time.Hour)
	tests := []struct {
		name  string
		auths []*Auth
		want  []string
	}{
		{"long window", []*Auth{resetAuth("a", late, early), resetAuth("b", early, late)}, []string{"b", "b"}},
		{"short window tie break", []*Auth{resetAuth("a", late, late), resetAuth("b", late, early)}, []string{"b", "b"}},
		{"unknown long window first", []*Auth{resetAuth("a", zero, early), resetAuth("b", late, zero)}, []string{"a", "a"}},
		{"unknown short window first", []*Auth{resetAuth("a", late, zero), resetAuth("b", late, early)}, []string{"a", "a"}},
		{"equal windows rotate", []*Auth{resetAuth("b", late, early), resetAuth("a", late, early)}, []string{"a", "b", "a"}},
		{"unknown windows rotate", []*Auth{resetAuth("b", zero, zero), resetAuth("a", zero, zero)}, []string{"a", "b", "a"}},
		{"expired windows first", []*Auth{resetAuth("a", now.Add(-time.Hour), early), resetAuth("b", late, zero)}, []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := &SoonestResetFirstSelector{}
			for _, want := range tt.want {
				got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, tt.auths)
				if err != nil || got == nil || got.ID != want {
					t.Fatalf("Pick() = %v, %v; want %s", got, err, want)
				}
			}
		})
	}
}

func TestSoonestResetFirstPriorityAndAvailability(t *testing.T) {
	now := time.Now()
	a, b := resetAuth("a", now.Add(time.Hour), time.Time{}), resetAuth("b", now.Add(24*time.Hour), time.Time{})
	b.Attributes = map[string]string{"priority": "10"}
	selector := &SoonestResetFirstSelector{}
	pick := func(want string) {
		t.Helper()
		got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{a, b})
		if err != nil || got == nil || got.ID != want {
			t.Fatalf("Pick() = %v, %v; want %s", got, err, want)
		}
	}
	pick("b")
	b.Disabled = true
	pick("a")
	b.Disabled = false
	b.Unavailable = true
	b.NextRetryAfter = now.Add(time.Hour)
	b.Quota.Exceeded = true
	b.Quota.NextRecoverAt = b.NextRetryAfter
	pick("a")
	a.Disabled = true
	if _, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{a, b}); err == nil {
		t.Fatal("exhausted and disabled auths must be excluded")
	}
}

func TestSoonestResetFirstSessionAffinity(t *testing.T) {
	now := time.Now()
	a, b := resetAuth("a", now.Add(time.Hour), time.Time{}), resetAuth("b", now.Add(24*time.Hour), time.Time{})
	selector := NewSessionAffinitySelector(&SoonestResetFirstSelector{})
	defer selector.Stop()
	opts := cliproxyexecutor.Options{OriginalRequest: []byte(`{"metadata":{"user_id":"user_xxx_account__session_ac980658-63bd-4fb3-97ba-8da64cb1e344"}}`)}
	pick := func(want string) {
		t.Helper()
		got, err := selector.Pick(context.Background(), "claude", "claude-3", opts, []*Auth{a, b})
		if err != nil || got == nil || got.ID != want {
			t.Fatalf("Pick() = %v, %v; want %s", got, err, want)
		}
	}
	pick("a")
	b.Quota.resetWindows.long.at = now.Add(time.Minute)
	b.Attributes = map[string]string{"priority": "10"}
	pick("a")
	a.Disabled = true
	pick("b")
}

func TestManagerCapturesResetHeaders(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		for _, success := range []bool{true, false} {
			t.Run(provider+"/success="+strconv.FormatBool(success), func(t *testing.T) {
				manager := NewManager(nil, &SoonestResetFirstSelector{}, nil)
				auth, err := manager.Register(context.Background(), &Auth{ID: "reset-" + provider, Provider: provider})
				if err != nil {
					t.Fatal(err)
				}
				headers := http.Header{}
				long, short := time.Now().Add(24*time.Hour).Truncate(time.Second), time.Now().Add(time.Hour).Truncate(time.Second)
				if provider == "claude" {
					headers.Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(long.Unix(), 10))
					headers.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(short.Unix(), 10))
				} else {
					headers.Set("x-codex-primary-reset-after-seconds", "3600")
					headers.Set("x-codex-secondary-reset-after-seconds", "86400")
				}
				ctx := internallogging.WithResponseHeadersHolder(context.Background())
				internallogging.SetResponseHeaders(ctx, headers)
				result := Result{AuthID: auth.ID, Provider: provider, Model: "test-model", Success: success}
				if !success {
					result.Error = &Error{HTTPStatus: 429, Message: "quota"}
				}
				manager.MarkResult(ctx, result)
				updated, ok := manager.GetByID(auth.ID)
				if !ok {
					t.Fatal("missing auth")
				}
				resets := updated.Quota.resetWindows
				if provider == "codex" {
					long = updated.Quota.ObservedAt.Add(24 * time.Hour)
					short = updated.Quota.ObservedAt.Add(time.Hour)
				}
				if !resets.long.at.Equal(long) || !resets.short.at.Equal(short) {
					t.Fatalf("resets = %+v; want long %v, short %v", resets, long, short)
				}
				if model := updated.ModelStates["test-model"]; model == nil || model.Quota.resetWindows != resets {
					t.Fatal("model reset observation missing")
				}
				// A subsequent response updates the short window without losing the weekly reset.
				next := http.Header{}
				if provider == "claude" {
					next.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(short.Add(time.Hour).Unix(), 10))
				} else {
					next.Set("x-codex-primary-reset-after-seconds", "7200")
				}
				internallogging.SetResponseHeaders(ctx, next)
				manager.MarkResult(ctx, result)
				latest, _ := manager.GetByID(auth.ID)
				if !latest.Quota.resetWindows.long.at.Equal(long) || !latest.Quota.resetWindows.short.at.After(short) {
					t.Fatalf("partial update lost or did not update resets: %+v", latest.Quota.resetWindows)
				}
			})
		}
	}
}

func TestQuotaResetWindowsCodexWindowLengths(t *testing.T) {
	now := time.Unix(1800000000, 0)
	var q QuotaState
	q.ObserveResponseHeadersForProvider("codex", http.Header{
		"x-codex-primary-window-minutes":      {"10080"},
		"x-codex-primary-reset-after-seconds": {"86400"},
		"x-codex-secondary-window-minutes":    {"300"},
		"x-codex-secondary-reset-at":          {strconv.FormatInt(now.Add(time.Hour).Unix(), 10)},
	}, now)
	if !q.resetWindows.long.at.Equal(now.Add(24*time.Hour)) || !q.resetWindows.short.at.Equal(now.Add(time.Hour)) {
		t.Fatalf("swapped windows: %+v", q.resetWindows)
	}
	before := q.resetWindows
	q.ObserveResponseHeadersForProvider("codex", http.Header{"X-Codex-Primary-Reset-After-Seconds": {"9223372036854775807"}, "X-Codex-Secondary-Reset-At": {"invalid"}}, now.Add(time.Second))
	if q.resetWindows != before {
		t.Fatal("invalid resets replaced known windows")
	}
	q.ObserveResponseHeadersForProvider("codex", http.Header{"X-Codex-Primary-Reset-After-Seconds": {"60"}, "X-Codex-Primary-Window-Minutes": {"10080"}}, now.Add(-time.Hour))
	if q.resetWindows != before {
		t.Fatal("older observation replaced newer window")
	}
}

func TestQuotaResetWindowsMergeAndClear(t *testing.T) {
	now := time.Now()
	existing := resetAuth("a", now.Add(24*time.Hour), now.Add(time.Hour))
	existing.Quota.resetWindows.long.observedAt = now
	existing.Quota.resetWindows.short.observedAt = now
	manager := NewManager(nil, nil, nil)
	if _, err := manager.Register(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	// File reloads and credential refreshes must preserve the in-memory deadlines.
	if _, err := manager.Update(context.Background(), &Auth{ID: "a", Provider: "claude"}); err != nil {
		t.Fatal(err)
	}
	updated, _ := manager.GetByID("a")
	if updated.Quota.resetWindows != existing.Quota.resetWindows {
		t.Fatalf("Update lost resets: %+v", updated.Quota.resetWindows)
	}
	// Reset observations clear independently of cooldown state.
	cleared := updated.Quota
	if !cleared.ClearObservationSignals() || cleared.resetWindows != (quotaResetWindows{}) {
		t.Fatal("clear did not remove reset observations")
	}
}

func TestManagerSoonestResetFirstSelection(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, sticky := range []bool{false, true} {
			name := "mixed=" + strconv.FormatBool(mixed) + "/sticky=" + strconv.FormatBool(sticky)
			t.Run(name, func(t *testing.T) {
				var selector Selector = &SoonestResetFirstSelector{}
				if sticky {
					affinity := NewSessionAffinitySelector(selector)
					defer affinity.Stop()
					selector = affinity
				}
				manager := NewManager(nil, selector, nil)
				manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
				model := "soonest-manager-model-" + name
				aID, bID := "soonest-manager-a-"+name, "soonest-manager-b-"+name
				now := time.Now()
				for _, auth := range []*Auth{resetAuth(aID, now.Add(24*time.Hour), time.Time{}), resetAuth(bID, now.Add(time.Hour), time.Time{})} {
					if _, err := manager.Register(context.Background(), auth); err != nil {
						t.Fatal(err)
					}
					registry.GetGlobalRegistry().RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: model}})
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
				}
				opts := cliproxyexecutor.Options{}
				if sticky {
					opts.Metadata = map[string]any{cliproxyexecutor.DerivedSessionIDMetadataKey: "soonest-manager-session-" + name}
				}
				pick := func(want string) {
					t.Helper()
					var got *Auth
					var err error
					if mixed {
						got, _, _, err = manager.pickNextMixed(context.Background(), []string{"claude"}, model, opts, nil)
					} else {
						got, _, err = manager.pickNext(context.Background(), "claude", model, opts, nil)
					}
					if err != nil || got == nil || got.ID != want {
						t.Fatalf("manager pick = %v, %v; want %s", got, err, want)
					}
				}
				pick(bID)
				ctx := internallogging.WithResponseHeadersHolder(context.Background())
				headers := http.Header{}
				headers.Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(now.Add(time.Minute).Unix(), 10))
				internallogging.SetResponseHeaders(ctx, headers)
				manager.MarkResult(ctx, Result{AuthID: aID, Provider: "claude", Model: model, Success: true})
				if sticky {
					pick(bID)
				} else {
					pick(aID)
				}
			})
		}
	}
}

func TestSoonestResetFirstUsesPrevalidatedCandidates(t *testing.T) {
	now := time.Now()
	a, b := resetAuth("a", now.Add(24*time.Hour), time.Time{}), resetAuth("b", now.Add(time.Hour), time.Time{})
	b.ModelStates = map[string]*ModelState{"route-alias": {Unavailable: true, NextRetryAfter: now.Add(time.Hour)}}
	selector := &SoonestResetFirstSelector{}
	// The manager resolved the alias against each auth's upstream model already.
	ctx := selectorContextForAvailableAuths(context.Background(), selector, "route-alias")
	got, err := selector.Pick(ctx, "claude", "route-alias", cliproxyexecutor.Options{}, []*Auth{a, b})
	if err != nil || got == nil || got.ID != "b" {
		t.Fatalf("prevalidated pick = %v, %v; want b", got, err)
	}
}

func TestManagerCapturesResetHeadersWhenQuotaSnapshotSkipped(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	if _, err := manager.Register(context.Background(), &Auth{ID: "count-reset", Provider: "claude"}); err != nil {
		t.Fatal(err)
	}
	ctx := internallogging.WithResponseHeadersHolder(context.Background())
	reset := time.Now().Add(time.Hour).Truncate(time.Second)
	headers := http.Header{}
	headers.Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(reset.Unix(), 10))
	internallogging.SetResponseHeaders(ctx, headers)
	manager.MarkResult(ctx, Result{AuthID: "count-reset", Provider: "claude", Success: true, SkipQuotaObservation: true})
	got, _ := manager.GetByID("count-reset")
	if !got.Quota.resetWindows.long.at.Equal(reset) {
		t.Fatalf("count-token reset = %v, want %v", got.Quota.resetWindows.long.at, reset)
	}
	if len(got.Quota.Signals) != 0 || !got.Quota.ObservedAt.IsZero() {
		t.Fatal("token count replaced the generation snapshot")
	}
}

func TestQuotaResetWindowsCodexUsesLongestReportedWindow(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, durations := range [][2]string{{"10080", "1440"}, {"60", "300"}} {
		var q QuotaState
		q.ObserveResponseHeadersForProvider("codex", http.Header{
			"X-Codex-Primary-Window-Minutes":        {durations[0]},
			"X-Codex-Secondary-Window-Minutes":      {durations[1]},
			"X-Codex-Primary-Reset-After-Seconds":   {"120"},
			"X-Codex-Secondary-Reset-After-Seconds": {"60"},
		}, now)
		wantLong, wantShort := now.Add(120*time.Second), now.Add(60*time.Second)
		if durations[0] == "60" {
			wantLong, wantShort = wantShort, wantLong
		}
		if !q.resetWindows.long.at.Equal(wantLong) || !q.resetWindows.short.at.Equal(wantShort) {
			t.Fatalf("durations %v: resets %+v, want long %v, short %v", durations, q.resetWindows, wantLong, wantShort)
		}
	}
}
