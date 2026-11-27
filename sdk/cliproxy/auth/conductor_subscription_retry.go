package auth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func isPaidClaudeFallback(auth *Auth) bool {
	return authPriority(auth) < 0 && executorKeyFromAuth(auth) == "claude" && auth.AuthKind() == AuthKindAPIKey
}

type claudeSubscriptionRetryKey struct{}
type claudeSubscriptionOnlyKey struct{}

// claudeSubscriptionRetry belongs to one execution, across all of its retry rounds.
type claudeSubscriptionRetry struct {
	transportErr   error
	deferredRounds int
}

func withClaudeSubscriptionRetry(ctx context.Context, providers []string) context.Context {
	if !slices.Contains(providers, "claude") {
		return ctx
	}
	return context.WithValue(ctx, claudeSubscriptionRetryKey{}, &claudeSubscriptionRetry{})
}

func subscriptionRetryFromContext(ctx context.Context) *claudeSubscriptionRetry {
	if ctx == nil {
		return nil
	}
	retry, _ := ctx.Value(claudeSubscriptionRetryKey{}).(*claudeSubscriptionRetry)
	return retry
}

func isClaudeSubscriptionTier(auth *Auth) bool {
	return executorKeyFromAuth(auth) == "claude" && authPriority(auth) >= 0
}

func temporaryPaidClaudeSelection(ctx context.Context, auth *Auth) bool {
	retry := subscriptionRetryFromContext(ctx)
	return retry != nil && retry.transportErr != nil && isPaidClaudeFallback(auth)
}

// A Fast request may wrap a pre-HTTP network error as request-scoped. The
// executor exposes that cause separately from failures of an accepted request.
func normalizeClaudeSubscriptionTransport(ctx context.Context, auth *Auth, err error) error {
	if subscriptionRetryFromContext(ctx) == nil || !isClaudeSubscriptionTier(auth) {
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

func (r *claudeSubscriptionRetry) observeFailure(ctx context.Context, auth *Auth, err error) {
	if r != nil && isClaudeSubscriptionTier(auth) && len(logging.GetResponseHeaders(ctx)) == 0 && isTransientTransportError(err) {
		r.transportErr = err
	}
}

func (r *claudeSubscriptionRetry) paidRetryRound(round int) int {
	if r != nil {
		return round - r.deferredRounds
	}
	return round
}

type claudeSubscriptionRetryError struct {
	cause error
	wait  time.Duration
}

func (e *claudeSubscriptionRetryError) Error() string { return e.cause.Error() }
func (e *claudeSubscriptionRetryError) Unwrap() error { return e.cause }

func (m *Manager) pickNextMixedWithSubscriptionRetry(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, round, defaultRetry int, attempted map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	retry := subscriptionRetryFromContext(ctx)
	if retry != nil && retry.transportErr != nil {
		subscriptionCtx := context.WithValue(ctx, claudeSubscriptionOnlyKey{}, true)
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
			return nil, nil, "", &claudeSubscriptionRetryError{cause: retry.transportErr, wait: wait}
		}
	}
	return m.pickNextMixed(ctx, providers, model, opts, tried)
}
