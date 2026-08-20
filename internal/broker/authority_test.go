package broker

import (
	"strings"
	"testing"
)

// This API-surface check closes a gap that import-graph checks cannot see: an
// allowed broker import must not re-export connector or policy capabilities.
func TestBrokerDoesNotReexportSecurityCapabilities(t *testing.T) {
	violations, err := scanBrokerPublicSurface(".")
	if err != nil {
		t.Fatalf("scan broker public surface: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("broker public API exposes security capabilities:\n%s", strings.Join(violations, "\n"))
	}
}
