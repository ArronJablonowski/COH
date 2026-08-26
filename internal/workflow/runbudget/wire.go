package runbudget

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

type planWire struct {
	SchemaVersion   string   `json:"schema_version"`
	ContractVersion string   `json:"contract_version"`
	RunID           string   `json:"run_id"`
	Case            caseWire `json:"case"`
	PolicyDigest    string   `json:"policy_digest"`
	ProviderRoute   string   `json:"provider_route"`
	Limits          Vector   `json:"limits"`
	CreatedAt       string   `json:"created_at"`
	ExpiresAt       string   `json:"expires_at"`
}

type reservationWire struct {
	ReservationDigest           string            `json:"reservation_digest"`
	ClaimDigest                 string            `json:"claim_digest"`
	SettlementDigest            string            `json:"settlement_digest"`
	SettlementIdempotencyDigest string            `json:"settlement_idempotency_digest"`
	IdempotencyDigest           string            `json:"idempotency_digest"`
	TaskID                      string            `json:"task_id"`
	ParentTaskID                string            `json:"parent_task_id"`
	Activity                    string            `json:"activity"`
	PolicyDigest                string            `json:"policy_digest"`
	ProviderRoute               string            `json:"provider_route"`
	Deadline                    string            `json:"deadline"`
	TaskLimits                  Vector            `json:"task_limits"`
	Claim                       Vector            `json:"claim"`
	Actual                      Vector            `json:"actual"`
	Outcome                     string            `json:"outcome"`
	Status                      ReservationStatus `json:"status"`
	CreatedAt                   string            `json:"created_at"`
	SettledAt                   string            `json:"settled_at"`
}

type ledgerWire struct {
	SchemaVersion            string            `json:"schema_version"`
	ContractVersion          string            `json:"contract_version"`
	RunID                    string            `json:"run_id"`
	Case                     caseWire          `json:"case"`
	PlanDigest               string            `json:"plan_digest"`
	PolicyDigest             string            `json:"policy_digest"`
	ProviderRoute            string            `json:"provider_route"`
	Limits                   Vector            `json:"limits"`
	Charged                  Vector            `json:"charged"`
	ActiveConcurrency        uint32            `json:"active_concurrency"`
	Reservations             []reservationWire `json:"reservations"`
	ReasonCode               string            `json:"reason_code"`
	PreviousProvenanceDigest string            `json:"previous_provenance_digest"`
	ProvenanceDigest         string            `json:"provenance_digest"`
	CreatedAt                string            `json:"created_at"`
	ExpiresAt                string            `json:"expires_at"`
	UpdatedAt                string            `json:"updated_at"`
	Revision                 uint64            `json:"revision"`
}

type caseWire struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

func CanonicalPlan(value Plan) ([]byte, error) {
	if err := validatePlan(value); err != nil {
		return nil, err
	}
	return canonicalValue(planToWire(value))
}

func DecodePlan(input []byte) (Plan, error) {
	var wire planWire
	if err := decodeExact(input, &wire); err != nil {
		return Plan{}, err
	}
	created, err := parseWireTime(wire.CreatedAt, false)
	if err != nil {
		return Plan{}, err
	}
	expires, err := parseWireTime(wire.ExpiresAt, false)
	if err != nil {
		return Plan{}, err
	}
	value := Plan{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion, RunID: wire.RunID,
		Case: caseFromWire(wire.Case), PolicyDigest: wire.PolicyDigest, ProviderRoute: wire.ProviderRoute,
		Limits: wire.Limits, CreatedAt: created, ExpiresAt: expires}
	return value, validatePlan(value)
}

func CanonicalLedger(value Ledger) ([]byte, error) {
	if err := validateLedger(value); err != nil {
		return nil, err
	}
	return canonicalValue(ledgerToWire(value))
}

func DecodeLedger(input []byte) (Ledger, error) {
	var wire ledgerWire
	if err := decodeExact(input, &wire); err != nil {
		return Ledger{}, err
	}
	value, err := ledgerFromWire(wire)
	if err != nil {
		return Ledger{}, err
	}
	return value, validateLedger(value)
}

func planToWire(value Plan) planWire {
	return planWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion, RunID: value.RunID,
		Case: caseToWire(value.Case), PolicyDigest: value.PolicyDigest, ProviderRoute: value.ProviderRoute,
		Limits: value.Limits, CreatedAt: formatTime(value.CreatedAt), ExpiresAt: formatTime(value.ExpiresAt)}
}

func ledgerToWire(value Ledger) ledgerWire {
	reservations := make([]reservationWire, len(value.Reservations))
	for index, record := range value.Reservations {
		settled := ""
		if !record.SettledAt.IsZero() {
			settled = formatTime(record.SettledAt)
		}
		reservations[index] = reservationWire{ReservationDigest: record.ReservationDigest,
			ClaimDigest: record.ClaimDigest, SettlementDigest: record.SettlementDigest,
			SettlementIdempotencyDigest: record.SettlementIdempotencyDigest,
			IdempotencyDigest:           record.IdempotencyDigest, TaskID: record.TaskID, ParentTaskID: record.ParentTaskID,
			Activity: record.Activity, PolicyDigest: record.PolicyDigest, ProviderRoute: record.ProviderRoute,
			Deadline: formatTime(record.Deadline), TaskLimits: record.TaskLimits, Claim: record.Claim,
			Actual: record.Actual, Outcome: record.Outcome, Status: record.Status,
			CreatedAt: formatTime(record.CreatedAt), SettledAt: settled}
	}
	return ledgerWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RunID: value.RunID, Case: caseToWire(value.Case), PlanDigest: value.PlanDigest, PolicyDigest: value.PolicyDigest,
		ProviderRoute: value.ProviderRoute, Limits: value.Limits, Charged: value.Charged,
		ActiveConcurrency: value.ActiveConcurrency, Reservations: reservations, ReasonCode: value.ReasonCode,
		PreviousProvenanceDigest: value.PreviousProvenanceDigest, ProvenanceDigest: value.ProvenanceDigest,
		CreatedAt: formatTime(value.CreatedAt), ExpiresAt: formatTime(value.ExpiresAt),
		UpdatedAt: formatTime(value.UpdatedAt), Revision: value.Revision}
}

func ledgerFromWire(wire ledgerWire) (Ledger, error) {
	created, err := parseWireTime(wire.CreatedAt, false)
	if err != nil {
		return Ledger{}, err
	}
	expires, err := parseWireTime(wire.ExpiresAt, false)
	if err != nil {
		return Ledger{}, err
	}
	updated, err := parseWireTime(wire.UpdatedAt, false)
	if err != nil {
		return Ledger{}, err
	}
	reservations := make([]ReservationRecord, len(wire.Reservations))
	for index, record := range wire.Reservations {
		deadline, parseErr := parseWireTime(record.Deadline, false)
		if parseErr != nil {
			return Ledger{}, parseErr
		}
		createdAt, parseErr := parseWireTime(record.CreatedAt, false)
		if parseErr != nil {
			return Ledger{}, parseErr
		}
		settledAt, parseErr := parseWireTime(record.SettledAt, true)
		if parseErr != nil {
			return Ledger{}, parseErr
		}
		reservations[index] = ReservationRecord{ReservationDigest: record.ReservationDigest,
			ClaimDigest: record.ClaimDigest, SettlementDigest: record.SettlementDigest,
			SettlementIdempotencyDigest: record.SettlementIdempotencyDigest,
			IdempotencyDigest:           record.IdempotencyDigest, TaskID: record.TaskID, ParentTaskID: record.ParentTaskID,
			Activity: record.Activity, PolicyDigest: record.PolicyDigest, ProviderRoute: record.ProviderRoute,
			Deadline: deadline, TaskLimits: record.TaskLimits, Claim: record.Claim, Actual: record.Actual,
			Outcome: record.Outcome, Status: record.Status, CreatedAt: createdAt, SettledAt: settledAt}
	}
	return Ledger{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion, RunID: wire.RunID,
		Case: caseFromWire(wire.Case), PlanDigest: wire.PlanDigest, PolicyDigest: wire.PolicyDigest,
		ProviderRoute: wire.ProviderRoute, Limits: wire.Limits, Charged: wire.Charged,
		ActiveConcurrency: wire.ActiveConcurrency, Reservations: reservations, ReasonCode: wire.ReasonCode,
		PreviousProvenanceDigest: wire.PreviousProvenanceDigest, ProvenanceDigest: wire.ProvenanceDigest,
		CreatedAt: created, ExpiresAt: expires, UpdatedAt: updated, Revision: wire.Revision}, nil
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func parseWireTime(value string, optional bool) (time.Time, error) {
	if value == "" && optional {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(Denied, "budget_timestamp_invalid", false, nil)
	}
	return parsed.UTC(), nil
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > maximumRecordBytes {
		return newError(Denied, "budget_record_size_invalid", false, nil)
	}
	decoded, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return newError(Denied, "budget_record_duplicate_or_malformed", false, nil)
	}
	target := reflect.TypeOf(output)
	if target == nil || target.Kind() != reflect.Pointer || !requiredFieldsPresent(decoded, target.Elem()) {
		return newError(Denied, "budget_record_required_field_missing", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "budget_record_malformed", false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "budget_record_trailing_data", false, nil)
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
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, child := range array {
			if !requiredFieldsPresent(child, target.Elem()) {
				return false
			}
		}
	}
	return true
}
