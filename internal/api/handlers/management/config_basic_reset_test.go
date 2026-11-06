package management

import "testing"

func TestNormalizeSoonestResetFirstRoutingStrategy(t *testing.T) {
	for _, input := range []string{"soonest-reset-first", " SOONEST-RESET-FIRST "} {
		got, ok := normalizeRoutingStrategy(input)
		if !ok || got != "soonest-reset-first" {
			t.Fatalf("normalizeRoutingStrategy(%q) = %q, %v", input, got, ok)
		}
	}
}
