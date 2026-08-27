package evidenceingest

import (
	"sort"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestParentManifestDigestsRemainPositionallyBoundToArtifactOrder(t *testing.T) {
	command := validCommand()
	command.Source.Kind = DerivedSource
	parents := []domain.ArtifactRef{
		{Digest: testDigest("parent-a"), MediaType: "application/json", Classification: "internal", Length: 10},
		{Digest: testDigest("parent-b"), MediaType: "application/json", Classification: "internal", Length: 20},
	}
	sort.Slice(parents, func(left, right int) bool { return parents[left].Digest < parents[right].Digest })
	command.ParentArtifacts = parents
	high, low := testDigest("manifest-high"), testDigest("manifest-low")
	if high < low {
		high, low = low, high
	}
	command.ParentManifestDigests = []string{high, low}
	if _, err := CanonicalCommand(command); err != nil {
		t.Fatalf("positionally bound parent pairs were rejected: %v", err)
	}
	authorization := validAuthorization(command)
	manifest := validManifest(command, authorization, validDecision(command, authorization))
	if _, err := CanonicalManifest(manifest); err != nil {
		t.Fatalf("positionally bound manifest pairs were rejected: %v", err)
	}

	for name, digests := range map[string][]string{
		"duplicate": {high, high},
		"malformed": {high, "not-a-digest"},
	} {
		t.Run(name, func(t *testing.T) {
			changed := command
			changed.ParentManifestDigests = digests
			if _, err := CanonicalCommand(changed); err == nil {
				t.Fatal("invalid parent manifest digests were accepted")
			}
		})
	}
}
