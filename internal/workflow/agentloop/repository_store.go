package agentloop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

type RepositoryStore struct{ repository workflowbase.Repository }

func NewRepositoryStore(repository workflowbase.Repository) (*RepositoryStore, error) {
	if repository == nil {
		return nil, newError(InvalidInput, "store", "repository_required", false, nil)
	}
	return &RepositoryStore{repository: repository}, nil
}

func (store *RepositoryStore) Create(ctx context.Context, idempotencyKey string, next Snapshot) (Snapshot, error) {
	if err := validateContext(ctx, "create"); err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshot(next); err != nil || !validInitialSnapshot(next) {
		return Snapshot{}, newError(InvalidInput, "create", "initial_state_invalid", false, nil)
	}
	return store.transact(ctx, idempotencyKey, Snapshot{}, next)
}

func (store *RepositoryStore) Load(ctx context.Context, scope domain.CaseRef, runID string) (Snapshot, error) {
	if err := validateContext(ctx, "load"); err != nil {
		return Snapshot{}, err
	}
	if !validateCase(scope) || !uuidV7Pattern.MatchString(runID) {
		return Snapshot{}, newError(InvalidInput, "load", "scope_invalid", false, nil)
	}
	runRecord, err := store.repository.Get(ctx, workflowbase.RecordKey{Case: scope, Kind: "run", ID: runID})
	if err != nil {
		return Snapshot{}, mapStorageError("load", err)
	}
	run, err := decodeRun(runRecord.Canonical)
	if err != nil {
		return Snapshot{}, err
	}
	stepRecord, err := store.repository.Get(ctx, workflowbase.RecordKey{Case: scope, Kind: "task", ID: run.CurrentStepID})
	if err != nil {
		return Snapshot{}, mapStorageError("load", err)
	}
	step, err := decodeStep(stepRecord.Canonical)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{Run: run, Step: step}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return cloneSnapshot(snapshot), nil
}

func (store *RepositoryStore) Save(ctx context.Context, idempotencyKey string, prior, next Snapshot) (Snapshot, error) {
	if err := validateContext(ctx, "save"); err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshot(prior); err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshot(next); err != nil {
		return Snapshot{}, err
	}
	if prior.Run.Case != next.Run.Case || prior.Run.RunID != next.Run.RunID || next.Run.Revision != prior.Run.Revision+1 || next.Run.Sequence != prior.Run.Sequence+1 {
		return Snapshot{}, newError(Conflict, "save", "run_revision_conflict", false, nil)
	}
	if err := validateTransition(prior, next); err != nil {
		return Snapshot{}, err
	}
	if prior.Step.StepID == next.Step.StepID {
		if next.Step.Revision != prior.Step.Revision+1 {
			return Snapshot{}, newError(Conflict, "save", "step_revision_conflict", false, nil)
		}
	} else if next.Step.Revision != 1 {
		return Snapshot{}, newError(Conflict, "save", "new_step_revision_invalid", false, nil)
	}
	return store.transact(ctx, idempotencyKey, prior, next)
}

func (store *RepositoryStore) transact(ctx context.Context, idempotencyKey string, prior, next Snapshot) (Snapshot, error) {
	if !validateOpaque(idempotencyKey, 256) {
		return Snapshot{}, newError(InvalidInput, "transact", "idempotency_key_invalid", false, nil)
	}
	runRecord, err := encodeRun(next.Run)
	if err != nil {
		return Snapshot{}, err
	}
	stepRecord, err := encodeStep(next.Step)
	if err != nil {
		return Snapshot{}, err
	}
	runExpected := uint64(0)
	stepExpected := uint64(0)
	if prior.Run.Revision > 0 {
		runExpected = prior.Run.Revision
		if prior.Step.StepID == next.Step.StepID {
			stepExpected = prior.Step.Revision
		}
	}
	mutations := []workflowbase.Mutation{
		{Kind: workflowbase.MutationPut, Key: runRecord.Key, ExpectedRevision: runExpected, Record: &runRecord},
		{Kind: workflowbase.MutationPut, Key: stepRecord.Key, ExpectedRevision: stepExpected, Record: &stepRecord},
	}
	sort.Slice(mutations, func(left, right int) bool { return recordKey(mutations[left].Key) < recordKey(mutations[right].Key) })
	eventID := deterministicUUID("COH-AGENT-LOOP-EVENT-ID-V1\x00", fmt.Sprintf("%s\x00%d", next.Run.RunID, next.Run.Sequence))
	transaction := workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion, IdempotencyKey: idempotencyKey, Mutations: mutations, Outbox: []workflowbase.OutboxMessage{{ID: eventID, Case: next.Run.Case, Topic: "agent_loop.transition", PayloadRef: fmt.Sprintf("coh-agent-loop://%s/%d", next.Run.RunID, next.Run.Sequence), PayloadDigest: next.Run.ProvenanceDigest}}}
	result, err := store.repository.Transact(ctx, transaction)
	if err != nil {
		return Snapshot{}, mapStorageError("transact", err)
	}
	if result.Replayed {
		stored, loadErr := store.Load(ctx, next.Run.Case, next.Run.RunID)
		if loadErr != nil {
			return Snapshot{}, loadErr
		}
		stored.Replayed = true
		return stored, nil
	}
	output := cloneSnapshot(next)
	return output, nil
}

type runEnvelope struct {
	Schema         string     `json:"schema"`
	Kind           string     `json:"kind"`
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	TenantID       string     `json:"tenant_id"`
	CaseID         string     `json:"case_id"`
	Revision       uint64     `json:"revision"`
	CreatedAt      string     `json:"created_at"`
	Data           runPayload `json:"data"`
}

type runPayload struct {
	ContractVersion   string   `json:"contract_version"`
	InitiatingActorID string   `json:"initiating_actor_id"`
	WorkflowType      string   `json:"workflow_type"`
	WorkflowVersion   string   `json:"workflow_version"`
	PolicyDigest      string   `json:"policy_digest"`
	ProviderRoute     string   `json:"provider_route"`
	BudgetPlanDigest  string   `json:"budget_plan_digest"`
	Status            string   `json:"status"`
	CurrentStepID     string   `json:"current_step_id"`
	Sequence          uint64   `json:"sequence"`
	InputRefs         []string `json:"input_refs"`
	OutputRefs        []string `json:"output_refs"`
	ProvenanceDigest  string   `json:"provenance_digest"`
	UpdatedAt         string   `json:"updated_at"`
}

type stepEnvelope struct {
	Schema         string      `json:"schema"`
	Kind           string      `json:"kind"`
	ID             string      `json:"id"`
	OrganizationID string      `json:"organization_id"`
	TenantID       string      `json:"tenant_id"`
	CaseID         string      `json:"case_id"`
	Revision       uint64      `json:"revision"`
	CreatedAt      string      `json:"created_at"`
	Data           stepPayload `json:"data"`
}

type stepPayload struct {
	ContractVersion         string   `json:"contract_version"`
	RunID                   string   `json:"run_id"`
	ActivityKind            string   `json:"activity_kind"`
	Status                  string   `json:"status"`
	Attempt                 uint32   `json:"attempt"`
	Deadline                string   `json:"deadline"`
	InputRefs               []string `json:"input_refs"`
	OutputRefs              []string `json:"output_refs"`
	IntentDigest            string   `json:"intent_digest"`
	ReceiptDigest           string   `json:"receipt_digest"`
	BudgetReservationDigest string   `json:"budget_reservation_digest"`
	BudgetSettlementDigest  string   `json:"budget_settlement_digest"`
	ProvenanceDigest        string   `json:"provenance_digest"`
	UpdatedAt               string   `json:"updated_at"`
}

func encodeRun(value Run) (workflowbase.MetadataRecord, error) {
	envelope := runEnvelope{
		Schema: RecordSchema, Kind: "run", ID: value.RunID,
		OrganizationID: value.Case.OrganizationID, TenantID: value.Case.TenantID, CaseID: value.Case.CaseID,
		Revision: value.Revision, CreatedAt: formatTime(value.CreatedAt),
		Data: runPayload{
			ContractVersion: value.ContractVersion, InitiatingActorID: value.ActorID,
			WorkflowType: WorkflowDefinition, WorkflowVersion: value.WorkflowVersion,
			PolicyDigest: value.PolicyDigest, ProviderRoute: value.ProviderRoute, Status: string(value.Status),
			BudgetPlanDigest: value.BudgetPlanDigest,
			CurrentStepID:    value.CurrentStepID, Sequence: value.Sequence,
			InputRefs: value.InputRefs, OutputRefs: value.OutputRefs,
			ProvenanceDigest: value.ProvenanceDigest, UpdatedAt: formatTime(value.UpdatedAt),
		},
	}
	return metadataRecord(value.Case, "run", value.RunID, value.Revision, envelope)
}

func encodeStep(value Step) (workflowbase.MetadataRecord, error) {
	envelope := stepEnvelope{
		Schema: RecordSchema, Kind: "task", ID: value.StepID,
		OrganizationID: value.Case.OrganizationID, TenantID: value.Case.TenantID, CaseID: value.Case.CaseID,
		Revision: value.Revision, CreatedAt: formatTime(value.CreatedAt),
		Data: stepPayload{
			ContractVersion: value.ContractVersion, RunID: value.RunID, ActivityKind: string(value.Kind), Status: string(value.Status),
			Attempt: value.Attempt, Deadline: formatTime(value.Deadline), InputRefs: value.InputRefs, OutputRefs: value.OutputRefs,
			IntentDigest: value.IntentDigest, ReceiptDigest: value.ReceiptDigest,
			BudgetReservationDigest: value.BudgetReservationDigest,
			BudgetSettlementDigest:  value.BudgetSettlementDigest,
			ProvenanceDigest:        value.ProvenanceDigest, UpdatedAt: formatTime(value.UpdatedAt),
		},
	}
	return metadataRecord(value.Case, "task", value.StepID, value.Revision, envelope)
}

func metadataRecord(scope domain.CaseRef, kind, id string, revision uint64, envelope any) (workflowbase.MetadataRecord, error) {
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	sum := sha256.Sum256(canonical)
	return workflowbase.MetadataRecord{Key: workflowbase.RecordKey{Case: scope, Kind: kind, ID: id}, Schema: RecordSchema, Revision: revision, Canonical: canonical, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func decodeRun(input []byte) (Run, error) {
	var value runEnvelope
	if err := decodeExact(input, &value); err != nil {
		return Run{}, err
	}
	created, err := parseTime(value.CreatedAt)
	if err != nil {
		return Run{}, err
	}
	updated, err := parseTime(value.Data.UpdatedAt)
	if err != nil {
		return Run{}, err
	}
	run := Run{
		ContractVersion: value.Data.ContractVersion, RunID: value.ID,
		Case:    domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID},
		ActorID: value.Data.InitiatingActorID, WorkflowVersion: value.Data.WorkflowVersion,
		PolicyDigest: value.Data.PolicyDigest, ProviderRoute: value.Data.ProviderRoute,
		BudgetPlanDigest: value.Data.BudgetPlanDigest,
		Status:           RunStatus(value.Data.Status), CurrentStepID: value.Data.CurrentStepID, Sequence: value.Data.Sequence,
		InputRefs: value.Data.InputRefs, OutputRefs: value.Data.OutputRefs,
		ProvenanceDigest: value.Data.ProvenanceDigest, CreatedAt: created, UpdatedAt: updated, Revision: value.Revision,
	}
	if value.Schema != RecordSchema || value.Kind != "run" || value.Data.WorkflowType != WorkflowDefinition {
		return Run{}, newError(Denied, "decode", "run_envelope_invalid", false, nil)
	}
	return run, validateRun(run)
}

func decodeStep(input []byte) (Step, error) {
	var value stepEnvelope
	if err := decodeExact(input, &value); err != nil {
		return Step{}, err
	}
	deadline, err := parseTime(value.Data.Deadline)
	if err != nil {
		return Step{}, err
	}
	created, err := parseTime(value.CreatedAt)
	if err != nil {
		return Step{}, err
	}
	updated, err := parseTime(value.Data.UpdatedAt)
	if err != nil {
		return Step{}, err
	}
	step := Step{
		ContractVersion: value.Data.ContractVersion, StepID: value.ID, RunID: value.Data.RunID,
		Case: domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID},
		Kind: ActivityKind(value.Data.ActivityKind), Status: StepStatus(value.Data.Status), Attempt: value.Data.Attempt,
		Deadline: deadline, InputRefs: value.Data.InputRefs, OutputRefs: value.Data.OutputRefs,
		IntentDigest: value.Data.IntentDigest, ReceiptDigest: value.Data.ReceiptDigest,
		BudgetReservationDigest: value.Data.BudgetReservationDigest,
		BudgetSettlementDigest:  value.Data.BudgetSettlementDigest,
		ProvenanceDigest:        value.Data.ProvenanceDigest, CreatedAt: created, UpdatedAt: updated, Revision: value.Revision,
	}
	if value.Schema != RecordSchema || value.Kind != "task" {
		return Step{}, newError(Denied, "decode", "step_envelope_invalid", false, nil)
	}
	return step, validateStep(step)
}

func formatTime(value time.Time) string { return value.UTC().Format(timestampLayout) }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		return time.Time{}, newError(Denied, "decode", "timestamp_invalid", false, nil)
	}
	return parsed.UTC(), nil
}

func mapStorageError(operation string, err error) error {
	switch workflowbase.StorageCode(err) {
	case workflowbase.StorageInvalidInput:
		return newError(InvalidInput, operation, "storage_input_invalid", false, nil)
	case workflowbase.StorageDenied:
		return newError(Denied, operation, "storage_denied", false, nil)
	case workflowbase.StorageNotFound:
		return newError(NotFound, operation, "state_not_found", false, nil)
	case workflowbase.StorageConflict:
		return newError(Conflict, operation, "state_conflict", false, nil)
	case workflowbase.StorageCanceled:
		return newError(Canceled, operation, "storage_canceled", false, err)
	case workflowbase.StorageTimeout:
		return newError(Timeout, operation, "storage_timeout", false, err)
	default:
		return newError(Unavailable, operation, "storage_unavailable", true, nil)
	}
}

func deterministicUUID(domain, input string) string {
	sum := sha256.Sum256([]byte(domain + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func recordKey(key workflowbase.RecordKey) string {
	return key.Case.OrganizationID + "/" + key.Case.TenantID + "/" + key.Case.CaseID + "/" + key.Kind + "/" + key.ID
}

func cloneSnapshot(value Snapshot) Snapshot {
	value.Run.InputRefs = append([]string{}, value.Run.InputRefs...)
	value.Run.OutputRefs = append([]string{}, value.Run.OutputRefs...)
	value.Step.InputRefs = append([]string{}, value.Step.InputRefs...)
	value.Step.OutputRefs = append([]string{}, value.Step.OutputRefs...)
	return value
}
