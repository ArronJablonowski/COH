package supplychain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRepositoryReleasePolicyAndFixtureKey(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, "ci", "release-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, digest, err := DecodePolicy(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !validDigest(digest) {
		t.Fatalf("policy digest=%q", digest)
	}
	trusted, err := LoadTrustedKey(root, policy, "ci-fixture")
	if err != nil {
		t.Fatal(err)
	}
	_, fixture, err := CIFixtureKey()
	if err != nil {
		t.Fatal(err)
	}
	if trusted.KeyID != fixture.KeyID || string(trusted.PublicPEM) != string(fixture.PublicPEM) {
		t.Fatal("repository fixture public key differs from derived CI fixture")
	}
	release, err := LoadTrustedKey(root, policy, "release")
	if err != nil {
		t.Fatal(err)
	}
	if release.KeyID != "sha256:659fb06ac3ca0943d312834773fed13dbde2c51239456939255317b412c9fe77" || release.Role != "release" {
		t.Fatal("repository release key differs from the pinned release authority")
	}
}

func TestSemanticVersionValidation(t *testing.T) {
	for _, value := range []string{"v0.1.0", "v1.2.3-rc.1", "v10.20.30-alpha-1"} {
		if !validVersion(value) {
			t.Fatalf("valid version rejected: %q", value)
		}
	}
	for _, value := range []string{"1.2.3", "v1.2", "v1.2.3.4", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2.3-", "v1.2.3-a..b", "v1.2.3+a"} {
		if validVersion(value) {
			t.Fatalf("invalid version accepted: %q", value)
		}
	}
}

func TestReleasePolicyRejectsUnknownDuplicateAndUnorderedValues(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, "ci", "release-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var canonical map[string]any
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
		code   ErrorCode
	}{
		{name: "unknown", mutate: func(value map[string]any) { value["extra"] = true }, code: CodeInvalidInput},
		{name: "duplicate target", mutate: func(value map[string]any) { value["targets"] = []any{"darwin/arm64", "darwin/arm64"} }, code: CodeDenied},
		{name: "unordered target", mutate: func(value map[string]any) { value["targets"] = []any{"linux/arm64", "darwin/arm64"} }, code: CodeDenied},
		{name: "archive subset", mutate: func(value map[string]any) { value["archive"] = value["archive"].([]any)[:1] }, code: CodeDenied},
		{name: "escaping key", mutate: func(value map[string]any) {
			keys := value["trusted_keys"].([]any)
			keys[0].(map[string]any)["public_key_path"] = "../key.pem"
		}, code: CodeDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyBytes, err := json.Marshal(canonical)
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err := json.Unmarshal(copyBytes, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			mutated, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := DecodePolicy(mutated); CodeOf(err) != test.code {
				t.Fatalf("code=%q err=%v", CodeOf(err), err)
			}
		})
	}
}
