package cliproxy

import (
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestSoonestResetFirstRoutingSelector(t *testing.T) {
	cfg, err := internalconfig.ParseConfigBytes([]byte("routing:\n  strategy: soonest-reset-first\n"))
	if err != nil {
		t.Fatal(err)
	}
	state := normalizedRoutingRuntimeState(cfg)
	if state.strategy != "soonest-reset-first" {
		t.Fatalf("strategy = %q", state.strategy)
	}
	if _, ok := newRoutingSelector(state).(*coreauth.SoonestResetFirstSelector); !ok {
		t.Fatalf("selector = %T", newRoutingSelector(state))
	}
	cfg.Routing.SessionAffinity = true
	selector := newRoutingSelector(normalizedRoutingRuntimeState(cfg))
	affinity, ok := selector.(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("affinity selector = %T", selector)
	}
	affinity.Stop()
	if _, ok := newRoutingSelector(normalizedRoutingRuntimeState(nil)).(*coreauth.RoundRobinSelector); !ok {
		t.Fatal("default strategy changed")
	}
}
