package recoverycontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

type caseWire struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type operationWire struct {
	ID      string   `json:"id"`
	Case    caseWire `json:"case"`
	Kind    string   `json:"kind"`
	Version string   `json:"version"`
}

type artifactWire struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type workWire struct {
	Case             caseWire        `json:"case"`
	RunID            string          `json:"run_id"`
	TaskID           string          `json:"task_id"`
	Status           WorkStatus      `json:"status"`
	SideEffect       SideEffectState `json:"side_effect"`
	IntentDigest     string          `json:"intent_digest"`
	ReceiptDigest    string          `json:"receipt_digest"`
	ProvenanceDigest string          `json:"provenance_digest"`
	TerminalEvidence string          `json:"terminal_evidence_digest"`
}

type routeWire struct {
	DecisionID     string            `json:"decision_id"`
	PolicyDigest   string            `json:"policy_digest"`
	RequestedRoute string            `json:"requested_route"`
	PrimaryRoute   string            `json:"primary_route"`
	FallbackRoute  string            `json:"fallback_route"`
	ApprovalDigest string            `json:"approval_digest"`
	Primary        CapabilityProfile `json:"primary"`
	Fallback       CapabilityProfile `json:"fallback"`
	IssuedAt       string            `json:"issued_at"`
	ExpiresAt      string            `json:"expires_at"`
}

type attemptWire struct {
	Sequence         uint32       `json:"sequence"`
	AttemptID        string       `json:"attempt_id"`
	Route            string       `json:"route"`
	CapabilityDigest string       `json:"capability_digest"`
	Status           Status       `json:"status"`
	Outcome          string       `json:"outcome"`
	Artifact         artifactWire `json:"artifact"`
	EvidenceDigest   string       `json:"evidence_digest"`
}

type recordWire struct {
	SchemaVersion            string            `json:"schema_version"`
	ContractVersion          string            `json:"contract_version"`
	ControlID                string            `json:"control_id"`
	Kind                     Kind              `json:"kind"`
	Case                     caseWire          `json:"case"`
	RunID                    string            `json:"run_id"`
	TaskID                   string            `json:"task_id"`
	PolicyDigest             string            `json:"policy_digest"`
	IntentDigest             string            `json:"intent_digest"`
	IdempotencyDigest        string            `json:"idempotency_digest"`
	ExpectedProvenanceDigest string            `json:"expected_provenance_digest"`
	ReasonDigest             string            `json:"reason_digest"`
	Operation                operationWire     `json:"operation"`
	InputRefs                []string          `json:"input_refs"`
	BudgetReservationDigest  string            `json:"budget_reservation_digest"`
	ObservedWork             workWire          `json:"observed_work"`
	ResultWork               workWire          `json:"result_work"`
	Targets                  []CancelTarget    `json:"targets"`
	Acknowledgments          []CancellationAck `json:"acknowledgments"`
	Route                    routeWire         `json:"route"`
	Attempts                 []attemptWire     `json:"attempts"`
	ResultArtifact           artifactWire      `json:"result_artifact"`
	Status                   Status            `json:"status"`
	ReasonCode               string            `json:"reason_code"`
	PreviousProvenanceDigest string            `json:"previous_provenance_digest"`
	ProvenanceDigest         string            `json:"provenance_digest"`
	CreatedAt                string            `json:"created_at"`
	Deadline                 string            `json:"deadline"`
	UpdatedAt                string            `json:"updated_at"`
	Revision                 uint64            `json:"revision"`
}

func CanonicalRecord(value Record) ([]byte, error) {
	if err := validateRecord(value); err != nil {
		return nil, err
	}
	return canonicalValue(recordToWire(value))
}

func recoverIntentDigest(value RecoverRequest) (string, error) {
	return intentValueDigest(RecoveryKind, struct {
		ControlID                string   `json:"control_id"`
		Case                     caseWire `json:"case"`
		RunID                    string   `json:"run_id"`
		TaskID                   string   `json:"task_id"`
		PolicyDigest             string   `json:"policy_digest"`
		ExpectedProvenanceDigest string   `json:"expected_provenance_digest"`
		IntentDigest             string   `json:"intent_digest"`
		CreatedAt                string   `json:"created_at"`
		Deadline                 string   `json:"deadline"`
	}{value.ControlID, caseToWire(value.Case), value.RunID, value.TaskID, value.PolicyDigest,
		value.ExpectedProvenanceDigest, value.IntentDigest, formatTime(value.CreatedAt), formatTime(value.Deadline)})
}

func cancelIntentDigest(value CancelRequest) (string, error) {
	return intentValueDigest(CancellationKind, struct {
		ControlID                string         `json:"control_id"`
		Case                     caseWire       `json:"case"`
		RunID                    string         `json:"run_id"`
		TaskID                   string         `json:"task_id"`
		PolicyDigest             string         `json:"policy_digest"`
		ExpectedProvenanceDigest string         `json:"expected_provenance_digest"`
		ReasonDigest             string         `json:"reason_digest"`
		Targets                  []CancelTarget `json:"targets"`
		CreatedAt                string         `json:"created_at"`
		Deadline                 string         `json:"deadline"`
	}{value.ControlID, caseToWire(value.Case), value.RunID, value.TaskID, value.PolicyDigest,
		value.ExpectedProvenanceDigest, value.ReasonDigest, cloneTargets(value.Targets),
		formatTime(value.CreatedAt), formatTime(value.Deadline)})
}

func invokeIntentDigest(value InvokeRequest) (string, error) {
	return intentValueDigest(FallbackKind, struct {
		ControlID               string        `json:"control_id"`
		Case                    caseWire      `json:"case"`
		RunID                   string        `json:"run_id"`
		TaskID                  string        `json:"task_id"`
		PolicyDigest            string        `json:"policy_digest"`
		RequestedRoute          string        `json:"requested_route"`
		Operation               operationWire `json:"operation"`
		InputRefs               []string      `json:"input_refs"`
		BudgetReservationDigest string        `json:"budget_reservation_digest"`
		CreatedAt               string        `json:"created_at"`
		Deadline                string        `json:"deadline"`
	}{value.ControlID, caseToWire(value.Case), value.RunID, value.TaskID, value.PolicyDigest,
		value.RequestedRoute, operationToWire(value.Operation), slices.Clone(value.InputRefs),
		value.BudgetReservationDigest, formatTime(value.CreatedAt), formatTime(value.Deadline)})
}

func recordIntentDigest(value Record) (string, error) {
	switch value.Kind {
	case RecoveryKind:
		return recoverIntentDigest(RecoverRequest{ControlID: value.ControlID, Case: value.Case, RunID: value.RunID,
			TaskID: value.TaskID, PolicyDigest: value.PolicyDigest,
			ExpectedProvenanceDigest: value.ExpectedProvenanceDigest, IntentDigest: value.ObservedWork.IntentDigest,
			CreatedAt: value.CreatedAt, Deadline: value.Deadline})
	case CancellationKind:
		return cancelIntentDigest(CancelRequest{ControlID: value.ControlID, Case: value.Case, RunID: value.RunID,
			TaskID: value.TaskID, PolicyDigest: value.PolicyDigest,
			ExpectedProvenanceDigest: value.ExpectedProvenanceDigest, ReasonDigest: value.ReasonDigest,
			Targets: value.Targets, CreatedAt: value.CreatedAt, Deadline: value.Deadline})
	case FallbackKind:
		return invokeIntentDigest(InvokeRequest{ControlID: value.ControlID, Case: value.Case, RunID: value.RunID,
			TaskID: value.TaskID, PolicyDigest: value.PolicyDigest, RequestedRoute: value.Route.RequestedRoute,
			Operation: value.Operation, InputRefs: value.InputRefs,
			BudgetReservationDigest: value.BudgetReservationDigest,
			CreatedAt:               value.CreatedAt, Deadline: value.Deadline})
	default:
		return "", newError(InvalidInput, "control_kind_invalid", false, false, nil)
	}
}

func intentValueDigest(kind Kind, value any) (string, error) {
	canonical, err := canonicalValue(value)
	if err != nil {
		return "", err
	}
	return compactDigest("COH-RECOVERY-CONTROL-INTENT-V1\x00"+string(kind)+"\x00", canonical), nil
}

func provenanceDigest(prior, reason string, value Record) (string, error) {
	copyValue := cloneRecord(value)
	copyValue.ProvenanceDigest = ""
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	payload := slices.Concat([]byte(prior), []byte{0}, []byte(reason), []byte{0}, canonical)
	return compactDigest("COH-RECOVERY-CONTROL-PROVENANCE-V1\x00", payload), nil
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Internal, "encoding_failed", false, false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(Internal, "canonicalization_failed", false, false, nil)
	}
	return canonical, nil
}

func compactDigest(domain string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domain), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func recordToWire(value Record) recordWire {
	attempts := make([]attemptWire, len(value.Attempts))
	for index, attempt := range value.Attempts {
		attempts[index] = attemptWire{Sequence: attempt.Sequence, AttemptID: attempt.AttemptID,
			Route: attempt.Route, CapabilityDigest: attempt.CapabilityDigest, Status: attempt.Status,
			Outcome: attempt.Outcome, Artifact: artifactToWire(attempt.Artifact), EvidenceDigest: attempt.EvidenceDigest}
	}
	return recordWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		ControlID: value.ControlID, Kind: value.Kind, Case: caseToWire(value.Case), RunID: value.RunID,
		TaskID: value.TaskID, PolicyDigest: value.PolicyDigest, IntentDigest: value.IntentDigest,
		IdempotencyDigest: value.IdempotencyDigest, ExpectedProvenanceDigest: value.ExpectedProvenanceDigest,
		ReasonDigest: value.ReasonDigest, Operation: operationToWire(value.Operation),
		InputRefs: slices.Clone(value.InputRefs), BudgetReservationDigest: value.BudgetReservationDigest,
		ObservedWork: workToWire(value.ObservedWork), ResultWork: workToWire(value.ResultWork),
		Targets: cloneTargets(value.Targets), Acknowledgments: cloneAcknowledgments(value.Acknowledgments),
		Route: routeToWire(value.Route), Attempts: attempts, ResultArtifact: artifactToWire(value.ResultArtifact),
		Status: value.Status, ReasonCode: value.ReasonCode,
		PreviousProvenanceDigest: value.PreviousProvenanceDigest, ProvenanceDigest: value.ProvenanceDigest,
		CreatedAt: formatTime(value.CreatedAt), Deadline: formatTime(value.Deadline),
		UpdatedAt: formatTime(value.UpdatedAt), Revision: value.Revision}
}

func routeToWire(value RouteBinding) routeWire {
	return routeWire{DecisionID: value.DecisionID, PolicyDigest: value.PolicyDigest,
		RequestedRoute: value.RequestedRoute, PrimaryRoute: value.PrimaryRoute,
		FallbackRoute: value.FallbackRoute, ApprovalDigest: value.ApprovalDigest,
		Primary: cloneProfile(value.Primary), Fallback: cloneProfile(value.Fallback),
		IssuedAt: formatOptionalTime(value.IssuedAt), ExpiresAt: formatOptionalTime(value.ExpiresAt)}
}

func workToWire(value WorkSnapshot) workWire {
	return workWire{Case: caseToWire(value.Case), RunID: value.RunID, TaskID: value.TaskID,
		Status: value.Status, SideEffect: value.SideEffect, IntentDigest: value.IntentDigest,
		ReceiptDigest: value.ReceiptDigest, ProvenanceDigest: value.ProvenanceDigest,
		TerminalEvidence: value.TerminalEvidence}
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func operationToWire(value domain.Operation) operationWire {
	return operationWire{ID: value.ID, Case: caseToWire(value.Case), Kind: value.Kind, Version: value.Version}
}

func artifactToWire(value domain.ArtifactRef) artifactWire {
	return artifactWire{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func formatTime(value time.Time) string { return value.UTC().Format(timestampLayout) }

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatTime(value)
}

func cloneRecord(value Record) Record {
	copyValue := value
	copyValue.InputRefs = slices.Clone(value.InputRefs)
	copyValue.Targets = cloneTargets(value.Targets)
	copyValue.Acknowledgments = cloneAcknowledgments(value.Acknowledgments)
	copyValue.Route.Primary = cloneProfile(value.Route.Primary)
	copyValue.Route.Fallback = cloneProfile(value.Route.Fallback)
	copyValue.Attempts = slices.Clone(value.Attempts)
	return copyValue
}

func cloneTargets(values []CancelTarget) []CancelTarget               { return slices.Clone(values) }
func cloneAcknowledgments(values []CancellationAck) []CancellationAck { return slices.Clone(values) }

func cloneProfile(value CapabilityProfile) CapabilityProfile {
	copyValue := value
	copyValue.MessageRoles = append([]string{}, value.MessageRoles...)
	copyValue.ContentKinds = append([]string{}, value.ContentKinds...)
	copyValue.StateModes = append([]string{}, value.StateModes...)
	return copyValue
}
