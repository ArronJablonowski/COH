package toolregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var manifestFields = []string{"schema_version", "contract_version", "manifest_id", "tool_name", "tool_version",
	"artifact_digest", "maximum_action_tier", "publisher_id", "review_id", "review_revision", "review_decision",
	"reviewer_actor_ids", "threat_model_digest", "reviewed_at", "valid_from", "valid_until", "operations"}

var operationFields = []string{"name", "input_schema_version", "input_fields", "baseline_action_tier",
	"maximum_action_tier", "isolation_class", "credential_classes", "resource_limits", "network_policy",
	"cancellation_mode", "retry_mode"}

var inputFieldFields = []string{"name", "type", "required", "minimum", "maximum", "maximum_bytes", "maximum_items", "enum"}
var resourceFields = []string{"wall_time_milliseconds", "cpu_milliseconds", "memory_bytes", "output_bytes",
	"ephemeral_storage_bytes", "process_count", "open_file_count"}
var networkFields = []string{"mode", "protocols", "dns_mode", "public_internet_allowed", "metadata_allowed", "maximum_connections"}

func Decode(ctx context.Context, input []byte) (ValidatedManifest, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedManifest{}, err
	}
	canonical, err := canonicalize(input)
	if err != nil {
		return ValidatedManifest{}, err
	}
	if err := validateJSONShape(canonical); err != nil {
		return ValidatedManifest{}, err
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return ValidatedManifest{}, NewError(InvalidInput, "manifest_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ValidatedManifest{}, NewError(InvalidInput, "manifest_decoding")
	}
	if err := Validate(manifest); err != nil {
		return ValidatedManifest{}, err
	}
	if err := contextError(ctx); err != nil {
		return ValidatedManifest{}, err
	}
	sum := sha256.Sum256(canonical)
	return ValidatedManifest{Digest: "sha256:" + hex.EncodeToString(sum[:]), manifest: cloneManifest(manifest),
		bytes: append([]byte(nil), canonical...)}, nil
}

func canonicalize(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return nil, NewError(InvalidInput, "manifest_size")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, NewError(InvalidInput, "manifest_decoding")
	}
	return canonical, nil
}

func validateJSONShape(input []byte) error {
	root, err := exactObject(input, manifestFields)
	if err != nil {
		return NewError(InvalidInput, "manifest_decoding")
	}
	var operations []json.RawMessage
	if err := json.Unmarshal(root["operations"], &operations); err != nil || operations == nil {
		return NewError(InvalidInput, "manifest_decoding")
	}
	for _, rawOperation := range operations {
		operation, objectErr := exactObject(rawOperation, operationFields)
		if objectErr != nil {
			return NewError(InvalidInput, "manifest_decoding")
		}
		if _, objectErr = exactObject(operation["resource_limits"], resourceFields); objectErr != nil {
			return NewError(InvalidInput, "manifest_decoding")
		}
		if _, objectErr = exactObject(operation["network_policy"], networkFields); objectErr != nil {
			return NewError(InvalidInput, "manifest_decoding")
		}
		var fields []json.RawMessage
		if err := json.Unmarshal(operation["input_fields"], &fields); err != nil || fields == nil {
			return NewError(InvalidInput, "manifest_decoding")
		}
		for _, field := range fields {
			if _, objectErr = exactObject(field, inputFieldFields); objectErr != nil {
				return NewError(InvalidInput, "manifest_decoding")
			}
		}
	}
	return nil
}

func exactObject(input []byte, required []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input, &fields); err != nil || len(fields) != len(required) {
		return nil, NewError(InvalidInput, "manifest_decoding")
	}
	for _, name := range required {
		if _, exists := fields[name]; !exists {
			return nil, NewError(InvalidInput, "manifest_decoding")
		}
	}
	return fields, nil
}

func cloneManifest(manifest Manifest) Manifest {
	cloned := manifest
	cloned.ReviewerActorIDs = cloneStrings(manifest.ReviewerActorIDs)
	cloned.Operations = make([]Operation, len(manifest.Operations))
	for index, operation := range manifest.Operations {
		cloned.Operations[index] = operation
		cloned.Operations[index].CredentialClasses = cloneStrings(operation.CredentialClasses)
		cloned.Operations[index].NetworkPolicy.Protocols = cloneStrings(operation.NetworkPolicy.Protocols)
		cloned.Operations[index].InputFields = make([]InputField, len(operation.InputFields))
		for fieldIndex, field := range operation.InputFields {
			cloned.Operations[index].InputFields[fieldIndex] = field
			cloned.Operations[index].InputFields[fieldIndex].Enum = cloneStrings(field.Enum)
			cloned.Operations[index].InputFields[fieldIndex].Minimum = cloneInt64(field.Minimum)
			cloned.Operations[index].InputFields[fieldIndex].Maximum = cloneInt64(field.Maximum)
		}
	}
	return cloned
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
