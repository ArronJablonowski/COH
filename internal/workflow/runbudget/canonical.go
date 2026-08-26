package runbudget

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func planDigest(value Plan) (string, error) {
	if err := validatePlan(value); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(struct {
		SchemaVersion   string   `json:"schema_version"`
		ContractVersion string   `json:"contract_version"`
		RunID           string   `json:"run_id"`
		Case            caseWire `json:"case"`
		PolicyDigest    string   `json:"policy_digest"`
		ProviderRoute   string   `json:"provider_route"`
		Limits          Vector   `json:"limits"`
		CreatedAt       string   `json:"created_at"`
		ExpiresAt       string   `json:"expires_at"`
	}{value.SchemaVersion, value.ContractVersion, value.RunID, caseToWire(value.Case), value.PolicyDigest,
		value.ProviderRoute, value.Limits, formatTime(value.CreatedAt), formatTime(value.ExpiresAt)})
	if err != nil {
		return "", err
	}
	return budgetDigest("COH-RUN-BUDGET-PLAN-V1\x00", canonical), nil
}

func claimDigest(value ReservationRequest, plan string) (string, error) {
	canonical, err := canonicalValue(struct {
		RunID         string   `json:"run_id"`
		TaskID        string   `json:"task_id"`
		ParentTaskID  string   `json:"parent_task_id"`
		Case          caseWire `json:"case"`
		Activity      string   `json:"activity"`
		PolicyDigest  string   `json:"policy_digest"`
		ProviderRoute string   `json:"provider_route"`
		Deadline      string   `json:"deadline"`
		PlanDigest    string   `json:"plan_digest"`
		TaskLimits    Vector   `json:"task_limits"`
		Claim         Vector   `json:"claim"`
	}{value.RunID, value.TaskID, value.ParentTaskID, caseToWire(value.Case), value.Activity, value.PolicyDigest,
		value.ProviderRoute, formatTime(value.Deadline), plan, value.TaskLimits, value.Claim})
	if err != nil {
		return "", err
	}
	return budgetDigest("COH-RUN-BUDGET-CLAIM-V1\x00", canonical), nil
}

func settlementDigest(reservation, idempotency string, actual Vector, outcome string) (string, error) {
	canonical, err := canonicalValue(struct {
		ReservationDigest string `json:"reservation_digest"`
		IdempotencyDigest string `json:"idempotency_digest"`
		Actual            Vector `json:"actual"`
		Outcome           string `json:"outcome"`
	}{reservation, idempotency, actual, outcome})
	if err != nil {
		return "", err
	}
	return budgetDigest("COH-RUN-BUDGET-SETTLEMENT-V1\x00", canonical), nil
}

func provenanceDigest(prior, operation string, value Ledger) (string, error) {
	copyValue := cloneLedger(value)
	copyValue.ProvenanceDigest = ""
	canonical, err := canonicalValue(ledgerToWire(copyValue))
	if err != nil {
		return "", err
	}
	payload := slices.Concat([]byte(prior), []byte{0}, []byte(operation), []byte{0}, canonical)
	return budgetDigest("COH-RUN-BUDGET-PROVENANCE-V1\x00", payload), nil
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Internal, "budget_encoding_failed", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(Internal, "budget_canonicalization_failed", false, nil)
	}
	return canonical, nil
}

func budgetDigest(domain string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domain), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func formatTime(value time.Time) string { return value.UTC().Format(timestampLayout) }

func cloneLedger(value Ledger) Ledger {
	copyValue := value
	copyValue.Reservations = append([]ReservationRecord{}, value.Reservations...)
	return copyValue
}
