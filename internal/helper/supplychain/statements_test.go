package supplychain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReleaseSBOMIsCanonicalAndBoundToArchive(t *testing.T) {
	archive := Artifact{Path: "coh-v0.1.0-darwin-arm64.tar.gz", SHA256: strings.Repeat("a", 64), Length: 42}
	entries := []ArchiveEntry{
		{Path: "bin/archcheck", Mode: 0o555, SHA256: strings.Repeat("b", 64), Length: 10},
		{Path: "bin/qualitygate", Mode: 0o555, SHA256: strings.Repeat("c", 64), Length: 20},
	}
	encoded, err := GenerateReleaseSBOM(archive, entries, "v0.1.0", "darwin/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReleaseSBOM(encoded, archive, entries, "v0.1.0", "darwin/arm64"); err != nil {
		t.Fatal(err)
	}
	archive.SHA256 = strings.Repeat("d", 64)
	if err := VerifyReleaseSBOM(encoded, archive, entries, "v0.1.0", "darwin/arm64"); CodeOf(err) != CodeDenied {
		t.Fatalf("counterfeit archive code=%q err=%v", CodeOf(err), err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	value["unexpected"] = true
	malformed, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReleaseSBOM(malformed, archive, entries, "v0.1.0", "darwin/arm64"); CodeOf(err) != CodeInvalidInput {
		t.Fatalf("unknown field code=%q err=%v", CodeOf(err), err)
	}
}

func TestSLSAProvenanceIsCanonicalAndBound(t *testing.T) {
	archive := Artifact{Path: "coh-v0.1.0-linux-amd64.tar.gz", SHA256: strings.Repeat("a", 64), Length: 42}
	source := Artifact{Path: "source", SHA256: strings.Repeat("b", 64), Length: 100}
	toolchain := Artifact{Path: "go", SHA256: strings.Repeat("c", 64), Length: 200}
	policy := Artifact{Path: "release-policy", SHA256: strings.Repeat("e", 64)}
	revision := strings.Repeat("d", 40)
	encoded, err := GenerateSLSAProvenance(archive, source, toolchain, policy, "v0.1.0", "linux/amd64", "go1.26.7", "https://github.com/ArronJablonowski/COH/actions", revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySLSAProvenance(encoded, archive, source, toolchain, policy, "v0.1.0", "linux/amd64", "go1.26.7", "https://github.com/ArronJablonowski/COH/actions", revision); err != nil {
		t.Fatal(err)
	}
	toolchain.SHA256 = strings.Repeat("e", 64)
	if err := VerifySLSAProvenance(encoded, archive, source, toolchain, policy, "v0.1.0", "linux/amd64", "go1.26.7", "https://github.com/ArronJablonowski/COH/actions", revision); CodeOf(err) != CodeDenied {
		t.Fatalf("toolchain drift code=%q err=%v", CodeOf(err), err)
	}
	policy.SHA256 = strings.Repeat("f", 64)
	if err := VerifySLSAProvenance(encoded, archive, source, Artifact{Path: "go", SHA256: strings.Repeat("c", 64), Length: 200}, policy, "v0.1.0", "linux/amd64", "go1.26.7", "https://github.com/ArronJablonowski/COH/actions", revision); CodeOf(err) != CodeDenied {
		t.Fatalf("policy drift code=%q err=%v", CodeOf(err), err)
	}
}
