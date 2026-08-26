package skillregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var manifestFields = []string{
	"schema_version", "contract_version", "manifest_id", "skill_name", "skill_version",
	"owner_actor_id", "publisher_actor_id", "content_digest", "resources", "permissions",
	"test_suite_digest", "test_evidence_digest", "threat_model_digest", "previous_manifest_digest",
	"review_id", "review_revision", "review_decision", "reviewer_actor_ids", "review_evidence_digest",
	"reviewed_at", "valid_from", "valid_until",
}

var resourceFields = []string{"name", "digest", "media_type", "classification", "length"}
var signatureFields = []string{
	"actor_id", "key_id", "key_revision", "approval_revision", "signature_algorithm", "signature",
}
var envelopeFields = []string{
	"schema_version", "contract_version", "manifest", "manifest_digest",
	"publisher_signature", "review_signatures",
}
var commandFields = []string{
	"schema_version", "contract_version", "command_id", "action", "organization_id", "tenant_id",
	"case_id", "task_id", "actor_id", "skill_name", "target_manifest_digest",
	"expected_current_digest", "expected_revision", "reason_digest", "created_at", "deadline",
}
var signedCommandFields = []string{
	"schema_version", "contract_version", "command", "command_digest", "signature",
}

type verifiedEnvelope struct {
	envelope      Envelope
	canonical     []byte
	manifestBytes []byte
}

type verifiedChange struct {
	value     SignedChange
	canonical []byte
	command   []byte
}

func decodeEnvelope(ctx context.Context, input []byte) (verifiedEnvelope, error) {
	if err := contextError(ctx); err != nil {
		return verifiedEnvelope{}, err
	}
	canonical, root, err := strictRoot(input, envelopeFields, "envelope_decoding")
	if err != nil {
		return verifiedEnvelope{}, err
	}
	if err := validateManifestShape(root["manifest"]); err != nil {
		return verifiedEnvelope{}, err
	}
	if _, err := exactObject(root["publisher_signature"], signatureFields); err != nil {
		return verifiedEnvelope{}, newError(InvalidInput, "envelope_decoding", false, err)
	}
	var reviewRaw []json.RawMessage
	if err := json.Unmarshal(root["review_signatures"], &reviewRaw); err != nil || reviewRaw == nil {
		return verifiedEnvelope{}, newError(InvalidInput, "envelope_decoding", false, err)
	}
	for _, raw := range reviewRaw {
		if _, err := exactObject(raw, signatureFields); err != nil {
			return verifiedEnvelope{}, newError(InvalidInput, "envelope_decoding", false, err)
		}
	}
	var envelope Envelope
	if err := decodeExact(canonical, &envelope); err != nil {
		return verifiedEnvelope{}, newError(InvalidInput, "envelope_decoding", false, err)
	}
	if envelope.SchemaVersion != EnvelopeSchemaVersion || envelope.ContractVersion != ContractVersion {
		return verifiedEnvelope{}, newError(Denied, "unsupported_envelope_contract", false, nil)
	}
	manifestBytes, digest, err := canonicalManifest(envelope.Manifest)
	if err != nil {
		return verifiedEnvelope{}, err
	}
	rawManifest, err := domaincontract.Canonicalize(root["manifest"])
	if err != nil || !bytes.Equal(rawManifest, manifestBytes) {
		return verifiedEnvelope{}, newError(Denied, "manifest_byte_drift", false, err)
	}
	if envelope.ManifestDigest != digest {
		return verifiedEnvelope{}, newError(Denied, "manifest_digest_mismatch", false, nil)
	}
	return verifiedEnvelope{envelope: envelope, canonical: canonical, manifestBytes: manifestBytes}, nil
}

func decodeChange(ctx context.Context, input []byte) (verifiedChange, error) {
	if err := contextError(ctx); err != nil {
		return verifiedChange{}, err
	}
	canonical, root, err := strictRoot(input, signedCommandFields, "command_envelope_decoding")
	if err != nil {
		return verifiedChange{}, err
	}
	if _, err := exactObject(root["command"], commandFields); err != nil {
		return verifiedChange{}, newError(InvalidInput, "command_decoding", false, err)
	}
	if _, err := exactObject(root["signature"], signatureFields); err != nil {
		return verifiedChange{}, newError(InvalidInput, "command_signature_decoding", false, err)
	}
	var value SignedChange
	if err := decodeExact(canonical, &value); err != nil {
		return verifiedChange{}, newError(InvalidInput, "command_envelope_decoding", false, err)
	}
	if value.SchemaVersion != SignedCommandVersion || value.ContractVersion != ContractVersion {
		return verifiedChange{}, newError(Denied, "unsupported_command_envelope", false, nil)
	}
	commandBytes, digest, err := canonicalCommand(value.Command)
	if err != nil {
		return verifiedChange{}, err
	}
	rawCommand, err := domaincontract.Canonicalize(root["command"])
	if err != nil || !bytes.Equal(rawCommand, commandBytes) {
		return verifiedChange{}, newError(Denied, "command_byte_drift", false, err)
	}
	if value.CommandDigest != digest {
		return verifiedChange{}, newError(Denied, "command_digest_mismatch", false, nil)
	}
	return verifiedChange{value: value, canonical: canonical, command: commandBytes}, nil
}

func validateManifestShape(input []byte) error {
	object, err := exactObject(input, manifestFields)
	if err != nil {
		return newError(InvalidInput, "manifest_decoding", false, err)
	}
	var resources []json.RawMessage
	if err := json.Unmarshal(object["resources"], &resources); err != nil || resources == nil {
		return newError(InvalidInput, "manifest_decoding", false, err)
	}
	for _, resource := range resources {
		if _, err := exactObject(resource, resourceFields); err != nil {
			return newError(InvalidInput, "manifest_decoding", false, err)
		}
	}
	return nil
}

func strictRoot(input []byte, fields []string, reason string) ([]byte, map[string]json.RawMessage, error) {
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return nil, nil, newError(InvalidInput, "input_size_invalid", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, nil, newError(InvalidInput, reason, false, err)
	}
	root, err := exactObject(canonical, fields)
	if err != nil {
		return nil, nil, newError(InvalidInput, reason, false, err)
	}
	return canonical, root, nil
}

func exactObject(input []byte, fields []string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(input, &object); err != nil || len(object) != len(fields) {
		return nil, newError(InvalidInput, "object_shape_invalid", false, err)
	}
	for _, field := range fields {
		if _, found := object[field]; !found {
			return nil, newError(InvalidInput, "object_shape_invalid", false, nil)
		}
	}
	return object, nil
}

func decodeExact(input []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(InvalidInput, "trailing_json", false, err)
	}
	return nil
}
