package actionmanifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func Decode(ctx context.Context, input []byte) (ValidatedManifest, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedManifest{}, err
	}
	canonical, err := canonicalize(input)
	if err != nil {
		return ValidatedManifest{}, err
	}
	if err := contextError(ctx); err != nil {
		return ValidatedManifest{}, err
	}
	manifest, err := decodeManifest(canonical)
	if err != nil {
		return ValidatedManifest{}, err
	}
	if err := Validate(manifest); err != nil {
		return ValidatedManifest{}, err
	}
	sum := sha256.Sum256(canonical)
	return ValidatedManifest{manifest: cloneManifest(manifest), Digest: "sha256:" + hex.EncodeToString(sum[:]), bytes: append([]byte(nil), canonical...)}, nil
}

func canonicalize(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return nil, contractError(InvalidInput, "manifest_size")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, contractError(InvalidInput, "manifest_decoding")
	}
	return canonical, nil
}

func decodeManifest(input []byte) (Manifest, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input, &fields); err != nil || len(fields) != len(requiredManifestFields) {
		return Manifest{}, contractError(InvalidInput, "manifest_decoding")
	}
	for _, field := range requiredManifestFields {
		if _, exists := fields[field]; !exists {
			return Manifest{}, contractError(InvalidInput, "manifest_decoding")
		}
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, contractError(InvalidInput, "manifest_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, contractError(InvalidInput, "manifest_decoding")
	}
	return manifest, nil
}

var requiredManifestFields = []string{
	"schema_version", "contract_version", "manifest_id", "workflow_task_id", "organization_id", "tenant_id", "case_id",
	"requestor_actor_id", "action_owner_actor_id", "action_type", "operation", "action_tier", "target_digests", "exclusion_digests",
	"arguments_digest", "tool", "payload_digest", "policy_digest", "policy_revision", "roe_digest", "credential_class",
	"credential_reference_digest", "execution_zone", "isolation_profile_digest", "valid_from", "valid_until", "manifest_nonce",
	"maximum_use_count", "rollback_digest", "safety_watch_actor_id",
}

func cloneManifest(manifest Manifest) Manifest {
	cloned := manifest
	cloned.TargetDigests = cloneStrings(manifest.TargetDigests)
	cloned.ExclusionDigests = cloneStrings(manifest.ExclusionDigests)
	cloned.ROEDigest = cloneString(manifest.ROEDigest)
	cloned.CredentialReferenceDigest = cloneString(manifest.CredentialReferenceDigest)
	cloned.RollbackDigest = cloneString(manifest.RollbackDigest)
	cloned.SafetyWatchActorID = cloneString(manifest.SafetyWatchActorID)
	return cloned
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
