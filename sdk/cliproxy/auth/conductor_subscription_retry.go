package auth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// isSubscriptionTier reports an OAuth subscription credential. It serves ahead
// of its provider's paid fallback keys.
func isSubscriptionTier(auth *Auth) bool {
	return auth != nil && authPriority(auth) >= 0 && auth.AuthKind() == AuthKindOAuth
}

// isPaidKey reports a priority -1 API key. It is a paid fallback only for a
// provider that also has a subscription; on an API-key-only route it is an
// ordinary low-priority key.
func isPaidKey(auth *Auth) bool {
	return auth != nil && authPriority(auth) < 0 && auth.AuthKind() == AuthKindAPIKey
}

// subscribedProviders returns the providers among auths that have a usable
// subscription credential.
func subscribedProviders(auths []*Auth) map[string]struct{} {
	var providers map[string]struct{}
	for _, auth := range auths {
		if isSubscriptionTier(auth) {
			if providers == nil {
				providers = make(map[string]struct{})
			}
			providers[executorKeyFromAuth(auth)] = struct{}{}
		}
	}
	return providers
}

type subscriptionRetryKey struct{}
type deferPaidKey struct{}

// subscriptionRetryState belongs to one execution, across all of its retry rounds.
type subscriptionRetryState struct {
	// paidProviders are the requested providers with both a subscription and a paid key.
	paidProviders     map[string]struct{}
	transportFailures map[string]error
	deferredRounds    map[string]int
	// Paid attempts already made in rounds that later deferred the provider.
	attemptedDuringDeferral map[string]int
}

// withSubscriptionRetry tracks subscription transport failures for requests
// whose providers have a paid fallback that must not absorb them. providers
// must be canonical (normalizeProviders), as executorKeyFromAuth is.
//
// The scan is linear in the registered credentials, like the retry-round
// checks that follow it, and runs once per request.
func (m *Manager) withSubscriptionRetry(ctx context.Context, providers []string) context.Context {
	if m == nil || len(providers) == 0 {
		return ctx
	}
	var candidates []*Auth
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, auth := range m.auths {
		if auth != nil && !auth.Disabled && auth.Status != StatusDisabled && slices.Contains(providers, executorKeyFromAuth(auth)) {
			candidates = append(candidates, auth)
		}
	}
	subscribed := subscribedProviders(candidates)
	paid := make(map[string]struct{})
	for _, auth := range candidates {
		if key := executorKeyFromAuth(auth); isPaidKey(auth) {
			if _, ok := subscribed[key]; ok {
				paid[key] = struct{}{}
			}
		}
	}
	if len(paid) == 0 {
		return ctx
	}
	return context.WithValue(ctx, subscriptionRetryKey{}, &subscriptionRetryState{
		paidProviders:           paid,
		transportFailures:       make(map[string]error),
		deferredRounds:          make(map[string]int),
		attemptedDuringDeferral: make(map[string]int),
	})
}

func subscriptionRetryFromContext(ctx context.Context) *subscriptionRetryState {
	if ctx == nil {
		return nil
	}
	retry, _ := ctx.Value(subscriptionRetryKey{}).(*subscriptionRetryState)
	return retry
}

func temporaryPaidSelection(ctx context.Context, auth *Auth) bool {
	retry := subscriptionRetryFromContext(ctx)
	return retry != nil && isPaidKey(auth) && retry.transportFailures[executorKeyFromAuth(auth)] != nil
}

// A Fast request may wrap a pre-HTTP network error as request-scoped. The
// executor exposes that cause separately from failures of an accepted request.
func normalizeSubscriptionTransport(ctx context.Context, auth *Auth, err error) error {
	retry := subscriptionRetryFromContext(ctx)
	if retry == nil || !isSubscriptionTier(auth) {
		return err
	}
	if _, ok := retry.paidProviders[executorKeyFromAuth(auth)]; !ok {
		return err
	}
	var preHTTP interface{ PreHTTPTransportError() error }
	if errors.As(err, &preHTTP) {
		if cause := preHTTP.PreHTTPTransportError(); isTransientTransportError(cause) {
			return cause
		}
	}
	return err
}

func (r *subscriptionRetryState) observeFailure(ctx context.Context, auth *Auth, err error) {
	if r == nil || !isSubscriptionTier(auth) {
		return
	}
	provider := executorKeyFromAuth(auth)
	if _, ok := r.paidProviders[provider]; ok && len(logging.GetResponseHeaders(ctx)) == 0 && isTransientTransportError(err) {
		r.transportFailures[provider] = err
	}
}

func (r *subscriptionRetryState) effectiveRound(auth *Auth, round int) int {
	if r == nil || !isPaidKey(auth) {
		return round
	}
	return round - r.deferredRounds[executorKeyFromAuth(auth)] + r.attemptedDuringDeferral[auth.ID]
}

// readySubscriptionRetries scans only subscriptions whose provider saw a
// transport failure. The next round must be able to pick one immediately.
func (m *Manager) readySubscriptionRetries(ctx context.Context, model string, opts cliproxyexecutor.Options, round, defaultRetry int, failures map[string]error) map[string]error {
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)
	registryRef := registry.GetGlobalRegistry()
	ready := make(map[string]error)

	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	for _, auth := range m.auths {
		provider := executorKeyFromAuth(auth)
		cause := failures[provider]
		if cause == nil || ready[provider] != nil || !isSubscriptionTier(auth) {
			continue
		}
		if !eligibility.allows(auth) || (pinnedAuthID != "" && auth.ID != pinnedAuthID) || round >= effectiveRequestRetryLimit(auth, defaultRetry) {
			continue
		}
		if _, ok := m.executorLocked(provider); !ok {
			continue
		}
		selectionModel := model
		if model != "" {
			if !m.authSupportsRouteModel(registryRef, auth, model) {
				continue
			}
			selectionModel = m.selectionModelForAuth(auth, model)
		}
		if blocked, _, _ := isAuthBlockedForModelForRequest(ctx, auth, selectionModel, now, opts.Headers); !blocked {
			ready[provider] = cause
		}
	}
	return ready
}

// subscriptionRetryError ends a retry round so the next one can retry a subscription.
type subscriptionRetryError struct {
	cause error
}

func (e *subscriptionRetryError) Error() string { return e.cause.Error() }
func (e *subscriptionRetryError) Unwrap() error { return e.cause }

func (m *Manager) pickNextMixedWithSubscriptionRetry(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, round, defaultRetry int, attempted map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	retry := subscriptionRetryFromContext(ctx)
	if retry == nil || len(retry.transportFailures) == 0 {
		return m.pickNextMixed(ctx, providers, model, opts, tried)
	}

	subscriptionCtx := context.WithValue(ctx, deferPaidKey{}, retry.transportFailures)
	auth, executor, provider, err := m.pickNextMixed(subscriptionCtx, providers, model, opts, tried)
	if !canReleasePaidFallbacks(err) {
		return auth, executor, provider, err
	}

	ready := m.readySubscriptionRetries(ctx, model, opts, round, defaultRetry, retry.transportFailures)
	if len(ready) == 0 {
		return m.pickNextMixed(ctx, providers, model, opts, tried)
	}
	if len(ready) < len(retry.transportFailures) {
		// One provider can release its paid keys while another can still retry
		// a subscription. Exhaust the newly eligible picks in this round.
		subscriptionCtx = context.WithValue(ctx, deferPaidKey{}, ready)
		auth, executor, provider, err = m.pickNextMixed(subscriptionCtx, providers, model, opts, tried)
		if !canReleasePaidFallbacks(err) {
			return auth, executor, provider, err
		}
	}

	var cause error
	for _, provider := range providers {
		if failure := ready[provider]; failure != nil {
			retry.deferredRounds[provider]++
			cause = failure
		}
	}
	m.mu.RLock()
	for id := range attempted {
		if auth := m.auths[id]; isPaidKey(auth) && ready[executorKeyFromAuth(auth)] != nil {
			retry.attemptedDuringDeferral[id]++
		}
	}
	m.mu.RUnlock()
	return nil, nil, "", &subscriptionRetryError{cause: cause}
}

func canReleasePaidFallbacks(err error) bool {
	var noAuth *Error
	return isAuthUnavailableError(err) || (errors.As(err, &noAuth) && noAuth != nil && noAuth.Code == "auth_not_found")
}
