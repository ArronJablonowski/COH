package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/helper/supplychain"
)

func TestReleaseAssemblyRequiresSigningKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run([]string{
		"-mode", "assemble", "-role", "release", "-bundle", "/tmp/bundle",
		"-go-binary", "/tmp/go",
	}, &stdout, &stderr)
	if status != 64 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "requires -signing-key") {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestProductionRoleCannotClaimHostedBuilderFromAmbientCI(t *testing.T) {
	policy := supplychain.Policy{BuilderIDs: []string{"hosted", "native"}}
	if actual := selectBuilder(policy, "release", true); actual != "native" {
		t.Fatalf("release builder=%q", actual)
	}
	if actual := selectBuilder(policy, "ci-fixture", true); actual != "hosted" {
		t.Fatalf("CI fixture builder=%q", actual)
	}
}

func TestSigningKeyRejectedOutsideReleaseAssembly(t *testing.T) {
	for _, arguments := range [][]string{
		{"-mode", "assemble", "-role", "ci-fixture", "-bundle", "/tmp/bundle", "-go-binary", "/tmp/go", "-signing-key", "/tmp/key"},
		{"-mode", "verify", "-role", "release", "-bundle", "/tmp/bundle", "-go-binary", "/tmp/go", "-signing-key", "/tmp/key"},
	} {
		var stdout, stderr bytes.Buffer
		status := run(arguments, &stdout, &stderr)
		if status != 64 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "accepted only") {
			t.Fatalf("arguments=%v status=%d stdout=%q stderr=%q", arguments, status, stdout.String(), stderr.String())
		}
	}
}
