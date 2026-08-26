package recoverycontrol

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

func DecodeRecord(input []byte) (Record, error) {
	var wire recordWire
	if err := decodeExact(input, &wire); err != nil {
		return Record{}, err
	}
	created, err := parseTime(wire.CreatedAt, false)
	if err != nil {
		return Record{}, err
	}
	deadline, err := parseTime(wire.Deadline, false)
	if err != nil {
		return Record{}, err
	}
	updated, err := parseTime(wire.UpdatedAt, false)
	if err != nil {
		return Record{}, err
	}
	issued, err := parseTime(wire.Route.IssuedAt, true)
	if err != nil {
		return Record{}, err
	}
	expires, err := parseTime(wire.Route.ExpiresAt, true)
	if err != nil {
		return Record{}, err
	}
	attempts := make([]ProviderAttempt, len(wire.Attempts))
	for index, attempt := range wire.Attempts {
		attempts[index] = ProviderAttempt{Sequence: attempt.Sequence, AttemptID: attempt.AttemptID,
			Route: attempt.Route, CapabilityDigest: attempt.CapabilityDigest, Status: attempt.Status,
			Outcome: attempt.Outcome, Artifact: artifactFromWire(attempt.Artifact),
			EvidenceDigest: attempt.EvidenceDigest}
	}
	value := Record{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion,
		ControlID: wire.ControlID, Kind: wire.Kind, Case: caseFromWire(wire.Case), RunID: wire.RunID,
		TaskID: wire.TaskID, PolicyDigest: wire.PolicyDigest, IntentDigest: wire.IntentDigest,
		IdempotencyDigest: wire.IdempotencyDigest, ExpectedProvenanceDigest: wire.ExpectedProvenanceDigest,
		ReasonDigest: wire.ReasonDigest, Operation: operationFromWire(wire.Operation),
		InputRefs: append([]string{}, wire.InputRefs...), BudgetReservationDigest: wire.BudgetReservationDigest,
		ObservedWork: workFromWire(wire.ObservedWork), ResultWork: workFromWire(wire.ResultWork),
		Targets: cloneTargets(wire.Targets), Acknowledgments: cloneAcknowledgments(wire.Acknowledgments),
		Route: routeFromWire(wire.Route, issued, expires), Attempts: attempts,
		ResultArtifact: artifactFromWire(wire.ResultArtifact), Status: wire.Status, ReasonCode: wire.ReasonCode,
		PreviousProvenanceDigest: wire.PreviousProvenanceDigest, ProvenanceDigest: wire.ProvenanceDigest,
		CreatedAt: created, Deadline: deadline, UpdatedAt: updated, Revision: wire.Revision}
	return value, validateRecord(value)
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > maximumRecordBytes {
		return newError(DeniedCode, "record_size_invalid", false, false, nil)
	}
	decoded, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return newError(DeniedCode, "record_duplicate_or_malformed", false, false, nil)
	}
	target := reflect.TypeOf(output)
	if target == nil || target.Kind() != reflect.Pointer || !requiredFieldsPresent(decoded, target.Elem()) {
		return newError(DeniedCode, "record_required_field_missing", false, false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(DeniedCode, "record_malformed", false, false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(DeniedCode, "record_trailing_data", false, false, nil)
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

func parseTime(value string, optional bool) (time.Time, error) {
	if optional && value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(DeniedCode, "record_timestamp_invalid", false, false, nil)
	}
	return parsed.UTC(), nil
}

func routeFromWire(value routeWire, issued, expires time.Time) RouteBinding {
	return RouteBinding{DecisionID: value.DecisionID, PolicyDigest: value.PolicyDigest,
		RequestedRoute: value.RequestedRoute, PrimaryRoute: value.PrimaryRoute,
		FallbackRoute: value.FallbackRoute, ApprovalDigest: value.ApprovalDigest,
		Primary: cloneProfile(value.Primary), Fallback: cloneProfile(value.Fallback),
		IssuedAt: issued, ExpiresAt: expires}
}

func workFromWire(value workWire) WorkSnapshot {
	return WorkSnapshot{Case: caseFromWire(value.Case), RunID: value.RunID, TaskID: value.TaskID,
		Status: value.Status, SideEffect: value.SideEffect, IntentDigest: value.IntentDigest,
		ReceiptDigest: value.ReceiptDigest, ProvenanceDigest: value.ProvenanceDigest,
		TerminalEvidence: value.TerminalEvidence}
}

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func operationFromWire(value operationWire) domain.Operation {
	return domain.Operation{ID: value.ID, Case: caseFromWire(value.Case), Kind: value.Kind, Version: value.Version}
}

func artifactFromWire(value artifactWire) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}
