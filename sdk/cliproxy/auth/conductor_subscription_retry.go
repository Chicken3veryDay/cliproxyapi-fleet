package auth

import (
	"context"
	"errors"
	"slices"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// isSubscriptionTier reports an OAuth subscription credential. It serves ahead
// of its provider's paid fallback keys.
func isSubscriptionTier(auth *Auth) bool {
	if auth == nil || authPriority(auth) < 0 {
		return false
	}
	switch auth.AuthKind() {
	case AuthKindOAuth:
		return true
	case AuthKindAPIKey:
		return false
	default:
		return auth.AuthSourceKind() == AuthSourceFile
	}
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
	paidProviders  map[string]struct{}
	transportErr   error
	deferredRounds int
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
	for _, auth := range m.auths {
		if auth != nil && !auth.Disabled && auth.Status != StatusDisabled && slices.Contains(providers, executorKeyFromAuth(auth)) {
			candidates = append(candidates, auth)
		}
	}
	m.mu.RUnlock()
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
	return context.WithValue(ctx, subscriptionRetryKey{}, &subscriptionRetryState{paidProviders: paid})
}

func subscriptionRetryFromContext(ctx context.Context) *subscriptionRetryState {
	if ctx == nil {
		return nil
	}
	retry, _ := ctx.Value(subscriptionRetryKey{}).(*subscriptionRetryState)
	return retry
}

// isPaidFallback reports a paid key whose provider's subscriptions serve first.
func (r *subscriptionRetryState) isPaidFallback(auth *Auth) bool {
	if r == nil || !isPaidKey(auth) {
		return false
	}
	_, ok := r.paidProviders[executorKeyFromAuth(auth)]
	return ok
}

func temporaryPaidSelection(ctx context.Context, auth *Auth) bool {
	retry := subscriptionRetryFromContext(ctx)
	return retry != nil && retry.transportErr != nil && retry.isPaidFallback(auth)
}

// A Fast request may wrap a pre-HTTP network error as request-scoped. The
// executor exposes that cause separately from failures of an accepted request.
func normalizeSubscriptionTransport(ctx context.Context, auth *Auth, err error) error {
	if subscriptionRetryFromContext(ctx) == nil || !isSubscriptionTier(auth) {
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
	if r != nil && isSubscriptionTier(auth) && len(logging.GetResponseHeaders(ctx)) == 0 && isTransientTransportError(err) {
		r.transportErr = err
	}
}

func (r *subscriptionRetryState) paidRetryRound(round int) int {
	if r != nil {
		return round - r.deferredRounds
	}
	return round
}

// subscriptionRetryError ends a retry round so the next one can retry a subscription.
type subscriptionRetryError struct {
	cause error
}

func (e *subscriptionRetryError) Error() string { return e.cause.Error() }
func (e *subscriptionRetryError) Unwrap() error { return e.cause }

func (m *Manager) pickNextMixedWithSubscriptionRetry(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, round, defaultRetry int, attempted map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	retry := subscriptionRetryFromContext(ctx)
	if retry != nil && retry.transportErr != nil {
		subscriptionCtx := context.WithValue(ctx, deferPaidKey{}, retry)
		auth, executor, provider, err := m.pickNextMixed(subscriptionCtx, providers, model, opts, tried)
		if err == nil {
			return auth, executor, provider, nil
		}
		var noAuth *Error
		if !isAuthUnavailableError(err) && !(errors.As(err, &noAuth) && noAuth.Code == "auth_not_found") {
			return nil, nil, "", err
		}
		_, _, maxWait := m.retrySettings()
		// Hold the paid keys back only while a subscription can be retried in
		// the next round. Once every subscription is cooling, e.g. after a 429
		// on its retry, a ready paid key serves the request.
		wait, canRetry := m.shouldRetryAfterErrorWithAttempted(subscriptionCtx, opts, retry.transportErr, round, providers, model, maxWait, -1, defaultRetry, attempted)
		if canRetry && wait == 0 {
			retry.deferredRounds++
			return nil, nil, "", &subscriptionRetryError{cause: retry.transportErr}
		}
	}
	return m.pickNextMixed(ctx, providers, model, opts, tried)
}
