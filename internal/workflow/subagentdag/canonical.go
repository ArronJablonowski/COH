package subagentdag

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

type taskWire struct {
	TaskID                   string                `json:"task_id"`
	ParentTaskIDs            []string              `json:"parent_task_ids"`
	Role                     Role                  `json:"role"`
	Status                   TaskStatus            `json:"status"`
	Depth                    uint32                `json:"depth"`
	InputRefs                []string              `json:"input_refs"`
	AssignmentDigest         string                `json:"assignment_digest"`
	BudgetReservationDigest  string                `json:"budget_reservation_digest"`
	BudgetSettlementDigest   string                `json:"budget_settlement_digest"`
	Result                   *structuredResultWire `json:"result"`
	Cancellation             *CancellationAck      `json:"cancellation"`
	PreviousProvenanceDigest string                `json:"previous_provenance_digest"`
	ProvenanceDigest         string                `json:"provenance_digest"`
	CreatedAt                string                `json:"created_at"`
	Deadline                 string                `json:"deadline"`
	UpdatedAt                string                `json:"updated_at"`
	Revision                 uint64                `json:"revision"`
}

type artifactWire struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type structuredResultWire struct {
	TaskID         string       `json:"task_id"`
	Role           Role         `json:"role"`
	Artifact       artifactWire `json:"artifact"`
	Claims         []Claim      `json:"claims"`
	Findings       []Finding    `json:"findings"`
	Completeness   Completeness `json:"completeness"`
	NegativeResult bool         `json:"negative_result"`
	RuntimeDigest  string       `json:"runtime_digest"`
	ResultDigest   string       `json:"result_digest"`
}

type caseWire struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type cancellationWire struct {
	CancellationID    string             `json:"cancellation_id"`
	RootTaskID        string             `json:"root_task_id"`
	ReasonDigest      string             `json:"reason_digest"`
	TargetTaskIDs     []string           `json:"target_task_ids"`
	Acknowledgments   []CancellationAck  `json:"acknowledgments"`
	Status            CancellationStatus `json:"status"`
	IntentDigest      string             `json:"intent_digest"`
	IdempotencyDigest string             `json:"idempotency_digest"`
	CreatedAt         string             `json:"created_at"`
	UpdatedAt         string             `json:"updated_at"`
	Revision          uint64             `json:"revision"`
}

type graphWire struct {
	SchemaVersion            string             `json:"schema_version"`
	ContractVersion          string             `json:"contract_version"`
	GraphID                  string             `json:"graph_id"`
	RunID                    string             `json:"run_id"`
	Case                     caseWire           `json:"case"`
	ActorID                  string             `json:"actor_id"`
	ActorRevision            uint64             `json:"actor_revision"`
	PolicyDigest             string             `json:"policy_digest"`
	ProviderRoute            string             `json:"provider_route"`
	Limits                   Limits             `json:"limits"`
	BudgetPlanDigest         string             `json:"budget_plan_digest"`
	Tasks                    []taskWire         `json:"tasks"`
	Edges                    []Edge             `json:"edges"`
	Receipts                 []Receipt          `json:"receipts"`
	Cancellations            []cancellationWire `json:"cancellations"`
	PreviousProvenanceDigest string             `json:"previous_provenance_digest"`
	ProvenanceDigest         string             `json:"provenance_digest"`
	CreatedAt                string             `json:"created_at"`
	Deadline                 string             `json:"deadline"`
	UpdatedAt                string             `json:"updated_at"`
	Revision                 uint64             `json:"revision"`
}

type decisionWire struct {
	SchemaVersion    string    `json:"schema_version"`
	ContractVersion  string    `json:"contract_version"`
	DecisionID       string    `json:"decision_id"`
	DecisionDigest   string    `json:"decision_digest"`
	IntentDigest     string    `json:"intent_digest"`
	Operation        Operation `json:"operation"`
	GraphID          string    `json:"graph_id"`
	TaskID           string    `json:"task_id"`
	Case             caseWire  `json:"case"`
	ActorID          string    `json:"actor_id"`
	ActorRevision    uint64    `json:"actor_revision"`
	PolicyDigest     string    `json:"policy_digest"`
	RevocationDigest string    `json:"revocation_digest"`
	Outcome          string    `json:"outcome"`
	ReasonCode       string    `json:"reason_code"`
	IssuedAt         string    `json:"issued_at"`
	ExpiresAt        string    `json:"expires_at"`
	Revision         uint64    `json:"revision"`
}

func DecisionBindingDigest(value Decision) (string, error) {
	copyValue := value
	copyValue.DecisionDigest = ""
	if err := validateDecisionShape(copyValue); err != nil {
		return "", err
	}
	encoded, err := canonicalValue(decisionToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-SUBAGENT-DAG-DECISION-V1\x00", encoded), nil
}

func ResultBindingDigest(value StructuredResult) (string, error) {
	copyValue := cloneStructuredResult(value)
	copyValue.ResultDigest = ""
	if err := validateStructuredResultShape(copyValue); err != nil {
		return "", err
	}
	encoded, err := canonicalValue(resultToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-SUBAGENT-DAG-RESULT-V1\x00", encoded), nil
}

func authorizationIntentDigest(value any) (string, error) {
	encoded, err := canonicalValue(value)
	if err != nil {
		return "", err
	}
	return digest("COH-SUBAGENT-DAG-INTENT-V1\x00", encoded), nil
}

func assignmentBindingDigest(value Task) (string, error) {
	bound := struct {
		TaskID        string   `json:"task_id"`
		ParentTaskIDs []string `json:"parent_task_ids"`
		Role          Role     `json:"role"`
		Depth         uint32   `json:"depth"`
		InputRefs     []string `json:"input_refs"`
		Deadline      string   `json:"deadline"`
	}{value.TaskID, append([]string{}, value.ParentTaskIDs...), value.Role, value.Depth,
		append([]string{}, value.InputRefs...), formatTime(value.Deadline)}
	encoded, err := canonicalValue(bound)
	if err != nil {
		return "", err
	}
	return digest("COH-SUBAGENT-DAG-ASSIGNMENT-V1\x00", encoded), nil
}

func taskProvenanceDigest(value Task) (string, error) {
	copyValue := cloneTask(value)
	copyValue.ProvenanceDigest = ""
	encoded, err := canonicalValue(taskToWire(copyValue))
	if err != nil {
		return "", err
	}
	payload := slices.Concat([]byte(value.PreviousProvenanceDigest), []byte{0}, encoded)
	return digest("COH-SUBAGENT-DAG-TASK-PROVENANCE-V1\x00", payload), nil
}

func graphProvenanceDigest(value Graph) (string, error) {
	copyValue := cloneGraph(value)
	copyValue.ProvenanceDigest = ""
	encoded, err := canonicalValue(graphToWire(copyValue))
	if err != nil {
		return "", err
	}
	payload := slices.Concat([]byte(value.PreviousProvenanceDigest), []byte{0}, encoded)
	return digest("COH-SUBAGENT-DAG-GRAPH-PROVENANCE-V1\x00", payload), nil
}

func idempotencyDigest(value string) string {
	return digest("COH-SUBAGENT-DAG-IDEMPOTENCY-V1\x00", []byte(value))
}

func taskToWire(value Task) taskWire {
	return taskWire{value.TaskID, append([]string{}, value.ParentTaskIDs...), value.Role, value.Status,
		value.Depth, append([]string{}, value.InputRefs...), value.AssignmentDigest,
		value.BudgetReservationDigest, value.BudgetSettlementDigest, resultPointerToWire(value.Result),
		cloneCancellation(value.Cancellation), value.PreviousProvenanceDigest, value.ProvenanceDigest,
		formatTime(value.CreatedAt), formatTime(value.Deadline), formatTime(value.UpdatedAt), value.Revision}
}

func resultToWire(value StructuredResult) structuredResultWire {
	return structuredResultWire{TaskID: value.TaskID, Role: value.Role,
		Artifact: artifactWire{Digest: value.Artifact.Digest, MediaType: value.Artifact.MediaType,
			Classification: value.Artifact.Classification, Length: value.Artifact.Length},
		Claims: append([]Claim{}, value.Claims...), Findings: append([]Finding{}, value.Findings...),
		Completeness: value.Completeness, NegativeResult: value.NegativeResult,
		RuntimeDigest: value.RuntimeDigest, ResultDigest: value.ResultDigest}
}

func resultFromWire(value structuredResultWire) StructuredResult {
	return StructuredResult{TaskID: value.TaskID, Role: value.Role,
		Artifact: domain.ArtifactRef{Digest: value.Artifact.Digest, MediaType: value.Artifact.MediaType,
			Classification: value.Artifact.Classification, Length: value.Artifact.Length},
		Claims: append([]Claim{}, value.Claims...), Findings: append([]Finding{}, value.Findings...),
		Completeness: value.Completeness, NegativeResult: value.NegativeResult,
		RuntimeDigest: value.RuntimeDigest, ResultDigest: value.ResultDigest}
}

func resultPointerToWire(value *StructuredResult) *structuredResultWire {
	if value == nil {
		return nil
	}
	result := resultToWire(*value)
	return &result
}

func resultPointerFromWire(value *structuredResultWire) *StructuredResult {
	if value == nil {
		return nil
	}
	result := resultFromWire(*value)
	return &result
}

func graphToWire(value Graph) graphWire {
	tasks := make([]taskWire, len(value.Tasks))
	for index := range value.Tasks {
		tasks[index] = taskToWire(value.Tasks[index])
	}
	cancellations := make([]cancellationWire, len(value.Cancellations))
	for index, item := range value.Cancellations {
		cancellations[index] = cancellationWire{CancellationID: item.CancellationID,
			RootTaskID: item.RootTaskID, ReasonDigest: item.ReasonDigest,
			TargetTaskIDs:   append([]string{}, item.TargetTaskIDs...),
			Acknowledgments: append([]CancellationAck{}, item.Acknowledgments...), Status: item.Status,
			IntentDigest: item.IntentDigest, IdempotencyDigest: item.IdempotencyDigest,
			CreatedAt: formatTime(item.CreatedAt), UpdatedAt: formatTime(item.UpdatedAt), Revision: item.Revision}
	}
	return graphWire{value.SchemaVersion, value.ContractVersion, value.GraphID, value.RunID,
		caseToWire(value.Case), value.ActorID, value.ActorRevision, value.PolicyDigest, value.ProviderRoute,
		value.Limits, value.BudgetPlanDigest, tasks, append([]Edge{}, value.Edges...),
		append([]Receipt{}, value.Receipts...), cancellations, value.PreviousProvenanceDigest,
		value.ProvenanceDigest, formatTime(value.CreatedAt), formatTime(value.Deadline),
		formatTime(value.UpdatedAt), value.Revision}
}

func decisionToWire(value Decision) decisionWire {
	return decisionWire{value.SchemaVersion, value.ContractVersion, value.DecisionID,
		value.DecisionDigest, value.IntentDigest, value.Operation, value.GraphID, value.TaskID,
		caseToWire(value.Case), value.ActorID, value.ActorRevision, value.PolicyDigest, value.RevocationDigest,
		value.Outcome, value.ReasonCode, formatTime(value.IssuedAt), formatTime(value.ExpiresAt), value.Revision}
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Internal, "encoding_failed", false, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(Internal, "canonicalization_failed", false, err)
	}
	return canonical, nil
}

func digest(domain string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domain), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timestampLayout)
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{value.OrganizationID, value.TenantID, value.CaseID}
}

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}
