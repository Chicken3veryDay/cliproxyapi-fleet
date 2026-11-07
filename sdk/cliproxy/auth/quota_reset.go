package auth

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Keep reset observations separate from the single-response signal snapshot: a
// response carrying only one window must not erase the other window's deadline.
type quotaWindowReset struct {
	at         time.Time
	observedAt time.Time
	// used is the consumed fraction of the window (0..1); usedKnown is false
	// when the upstream did not report it.
	used      float64
	usedKnown bool
}

type quotaResetWindows struct {
	long  quotaWindowReset
	short quotaWindowReset
}

func mergeQuotaResetWindows(target, source quotaResetWindows) quotaResetWindows {
	if source.long.observedAt.After(target.long.observedAt) {
		target.long = source.long
	}
	if source.short.observedAt.After(target.short.observedAt) {
		target.short = source.short
	}
	return target
}

func (w *quotaResetWindows) observe(provider string, signals map[string]string, now time.Time) {
	update := func(dst *quotaWindowReset, at time.Time, used float64, usedKnown bool) {
		if !at.IsZero() && !now.Before(dst.observedAt) {
			*dst = quotaWindowReset{at: at, observedAt: now, used: used, usedKnown: usedKnown}
		}
	}
	fraction := func(raw string, scale float64) (float64, bool) {
		v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || v < 0 || v != v {
			return 0, false
		}
		return min(v/scale, 1), true
	}
	value := func(name string) string { return signals[http.CanonicalHeaderKey(name)] }
	unixReset := func(raw string) time.Time {
		seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || seconds <= 0 {
			return time.Time{}
		}
		return time.Unix(seconds, 0)
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		longUsed, longKnown := fraction(value("anthropic-ratelimit-unified-7d-utilization"), 1)
		shortUsed, shortKnown := fraction(value("anthropic-ratelimit-unified-5h-utilization"), 1)
		update(&w.long, unixReset(value("anthropic-ratelimit-unified-7d-reset")), longUsed, longKnown)
		update(&w.short, unixReset(value("anthropic-ratelimit-unified-5h-reset")), shortUsed, shortKnown)
	case "codex":
		primaryMinutes, _ := strconv.ParseInt(value("x-codex-primary-window-minutes"), 10, 64)
		secondaryMinutes, _ := strconv.ParseInt(value("x-codex-secondary-window-minutes"), 10, 64)
		for _, window := range []string{"primary", "secondary"} {
			prefix := "x-codex-" + window + "-"
			at := unixReset(value(prefix + "reset-at"))
			if at.IsZero() {
				seconds, err := strconv.ParseInt(value(prefix+"reset-after-seconds"), 10, 64)
				// Bound conversion to time.Duration; invalid upstream values stay unknown.
				if err == nil && seconds >= 0 && seconds <= int64((1<<63-1)/time.Second) {
					at = now.Add(time.Duration(seconds) * time.Second)
				}
			}
			// Primary is normally 5h and secondary 7d, but some plans swap
			// them or report only a weekly primary. Use window length when present.
			minutes, _ := strconv.ParseInt(value(prefix+"window-minutes"), 10, 64)
			long := window == "secondary"
			if primaryMinutes > 0 && secondaryMinutes > 0 && primaryMinutes != secondaryMinutes {
				long = minutes == max(primaryMinutes, secondaryMinutes)
			} else if minutes > 0 {
				long = minutes > 300
			}
			used, usedKnown := fraction(value(prefix+"used-percent"), 100)
			if long {
				update(&w.long, at, used, usedKnown)
			} else {
				update(&w.short, at, used, usedKnown)
			}
		}
	}
}
