package contextcompact

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumRecordBytes = 1 << 20

func DecodeIntent(input []byte) (Intent, error) {
	var wire intentWire
	if err := decodeExact(input, &wire); err != nil {
		return Intent{}, err
	}
	created, err := parseWireTime(wire.CreatedAt)
	if err != nil {
		return Intent{}, err
	}
	deadline, err := parseWireTime(wire.Deadline)
	if err != nil {
		return Intent{}, err
	}
	value := Intent{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion,
		CompactionID: wire.CompactionID, RunID: wire.RunID, TaskID: wire.TaskID, Case: caseFromWire(wire.Case),
		PolicyDigest: wire.PolicyDigest, ProviderRoute: wire.ProviderRoute, Sources: cloneSources(wire.Sources),
		CreatedAt: created, Deadline: deadline}
	return value, validateIntent(value)
}

func DecodeState(input []byte) (State, error) {
	var wire stateWire
	if err := decodeExact(input, &wire); err != nil {
		return State{}, err
	}
	created, err := parseWireTime(wire.CreatedAt)
	if err != nil {
		return State{}, err
	}
	deadline, err := parseWireTime(wire.Deadline)
	if err != nil {
		return State{}, err
	}
	updated, err := parseWireTime(wire.UpdatedAt)
	if err != nil {
		return State{}, err
	}
	value := State{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion,
		CompactionID: wire.CompactionID, RunID: wire.RunID, TaskID: wire.TaskID, Case: caseFromWire(wire.Case),
		PolicyDigest: wire.PolicyDigest, ProviderRoute: wire.ProviderRoute, Sources: cloneSources(wire.Sources),
		SourceManifestDigest: wire.SourceManifestDigest, IntentDigest: wire.IntentDigest,
		IdempotencyDigest: wire.IdempotencyDigest,
		Summary:           artifactFromWire(wire.Summary), SummaryTrust: wire.SummaryTrust,
		Status: wire.Status, ReasonCode: wire.ReasonCode,
		PreviousProvenanceDigest: wire.PreviousProvenanceDigest, ProvenanceDigest: wire.ProvenanceDigest,
		CreatedAt: created, Deadline: deadline, UpdatedAt: updated, Revision: wire.Revision}
	return value, validateState(value)
}

func parseWireTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(Denied, "compaction_timestamp_invalid", false, nil)
	}
	return parsed.UTC(), nil
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > maximumRecordBytes {
		return newError(Denied, "compaction_record_size_invalid", false, nil)
	}
	decoded, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return newError(Denied, "compaction_record_duplicate_or_malformed", false, nil)
	}
	target := reflect.TypeOf(output)
	if target == nil || target.Kind() != reflect.Pointer || !requiredFieldsPresent(decoded, target.Elem()) {
		return newError(Denied, "compaction_record_required_field_missing", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "compaction_record_malformed", false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "compaction_record_trailing_data", false, nil)
	}
	return nil
}

func requiredFieldsPresent(value any, target reflect.Type) bool {
	if target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			child, found := object[name]
			if !found || !requiredFieldsPresent(child, field.Type) {
				return false
			}
		}
		return true
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if !requiredFieldsPresent(item, target.Elem()) {
				return false
			}
		}
	}
	return true
}

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func artifactFromWire(value artifactWire) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}
