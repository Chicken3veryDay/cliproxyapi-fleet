package auth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// A paid fallback is a priority -1 API key. Any higher-priority credential of
// the same provider is a subscription tier that should serve first.
func isPaidFallback(auth *Auth) bool {
	return authPriority(auth) < 0 && auth.AuthKind() == AuthKindAPIKey
}

type subscriptionRetryKey struct{}
type subscriptionOnlyKey struct{}

// subscriptionRetryState belongs to one execution, across all of its retry rounds.
type subscriptionRetryState struct {
	transportErr   error
	deferredRounds int
}

// withSubscriptionRetry tracks subscription transport failures for requests
// whose providers have a paid fallback that must not absorb them.
func (m *Manager) withSubscriptionRetry(ctx context.Context, providers []string) context.Context {
	if m == nil {
		return ctx
	}
	m.mu.RLock()
	hasPaidFallback := false
	for _, auth := range m.auths {
		if isPaidFallback(auth) && slices.Contains(providers, executorKeyFromAuth(auth)) {
			hasPaidFallback = true
			break
		}
	}
	m.mu.RUnlock()
	if !hasPaidFallback {
		return ctx
	}
	return context.WithValue(ctx, subscriptionRetryKey{}, &subscriptionRetryState{})
}

func subscriptionRetryFromContext(ctx context.Context) *subscriptionRetryState {
	if ctx == nil {
		return nil
	}
	retry, _ := ctx.Value(subscriptionRetryKey{}).(*subscriptionRetryState)
	return retry
}

func isSubscriptionTier(auth *Auth) bool {
	return auth != nil && authPriority(auth) >= 0
}

func temporaryPaidSelection(ctx context.Context, auth *Auth) bool {
	retry := subscriptionRetryFromContext(ctx)
	return retry != nil && retry.transportErr != nil && isPaidFallback(auth)
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

type subscriptionRetryError struct {
	cause error
	wait  time.Duration
}

func (e *subscriptionRetryError) Error() string { return e.cause.Error() }
func (e *subscriptionRetryError) Unwrap() error { return e.cause }

func (m *Manager) pickNextMixedWithSubscriptionRetry(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, round, defaultRetry int, attempted map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	retry := subscriptionRetryFromContext(ctx)
	if retry != nil && retry.transportErr != nil {
		subscriptionCtx := context.WithValue(ctx, subscriptionOnlyKey{}, true)
		auth, executor, provider, err := m.pickNextMixed(subscriptionCtx, providers, model, opts, tried)
		if err == nil {
			return auth, executor, provider, nil
		}
		var noAuth *Error
		if !isAuthUnavailableError(err) && !(errors.As(err, &noAuth) && noAuth.Code == "auth_not_found") {
			return nil, nil, "", err
		}
		_, _, maxWait := m.retrySettings()
		wait, canRetry := m.shouldRetryAfterErrorWithAttempted(subscriptionCtx, opts, retry.transportErr, round, providers, model, maxWait, -1, defaultRetry, attempted)
		if canRetry {
			retry.deferredRounds++
			return nil, nil, "", &subscriptionRetryError{cause: retry.transportErr, wait: wait}
		}
	}
	return m.pickNextMixed(ctx, providers, model, opts, tried)
}
