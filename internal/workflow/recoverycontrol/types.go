// Package recoverycontrol coordinates safe workflow recovery, durable
// cancellation propagation, and policy-approved provider fallback.
package recoverycontrol

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	SchemaVersion   = "coh.recovery-control/v1"
	ContractVersion = "1.0.0"
	MaximumTargets  = 512
	MaximumInputs   = 512
)

type Kind string

const (
	RecoveryKind     Kind = "recovery"
	CancellationKind Kind = "cancellation"
	FallbackKind     Kind = "fallback"
)

type Status string

const (
	RecoveryPrepared   Status = "recovery_prepared"
	CancellationActive Status = "cancellation_active"
	PrimaryAttempting  Status = "primary_attempting"
	PrimaryUnavailable Status = "primary_unavailable"
	FallbackAttempting Status = "fallback_attempting"
	Completed          Status = "completed"
	Failed             Status = "failed"
	Denied             Status = "denied"
	Canceled           Status = "canceled"
	TimedOut           Status = "timeout"
	Uncertain          Status = "uncertain"
)

type WorkStatus string

const (
	WorkPending   WorkStatus = "pending"
	WorkRunning   WorkStatus = "running"
	WorkWaiting   WorkStatus = "waiting"
	WorkSucceeded WorkStatus = "succeeded"
	WorkFailed    WorkStatus = "failed"
	WorkDenied    WorkStatus = "denied"
	WorkCanceled  WorkStatus = "canceled"
	WorkTimeout   WorkStatus = "timeout"
	WorkUncertain WorkStatus = "uncertain"
)

type SideEffectState string

const (
	NoSideEffect            SideEffectState = "none"
	ConfirmedSideEffect     SideEffectState = "confirmed"
	IndeterminateSideEffect SideEffectState = "indeterminate"
)

type WorkSnapshot struct {
	Case             domain.CaseRef  `json:"case"`
	RunID            string          `json:"run_id"`
	TaskID           string          `json:"task_id"`
	Status           WorkStatus      `json:"status"`
	SideEffect       SideEffectState `json:"side_effect"`
	IntentDigest     string          `json:"intent_digest"`
	ReceiptDigest    string          `json:"receipt_digest"`
	ProvenanceDigest string          `json:"provenance_digest"`
	TerminalEvidence string          `json:"terminal_evidence_digest"`
}

type TargetKind string

const (
	ChildTask TargetKind = "child_task"
	ToolJob   TargetKind = "tool_job"
)

type CancelTarget struct {
	Sequence                 uint32     `json:"sequence"`
	Kind                     TargetKind `json:"kind"`
	TargetID                 string     `json:"target_id"`
	ExpectedProvenanceDigest string     `json:"expected_provenance_digest"`
}

type AckOutcome string

const (
	AckCanceled        AckOutcome = "canceled"
	AckAlreadyTerminal AckOutcome = "already_terminal"
	AckUncertain       AckOutcome = "uncertain"
)

type CancellationAck struct {
	Sequence         uint32     `json:"sequence"`
	Kind             TargetKind `json:"kind"`
	TargetID         string     `json:"target_id"`
	Outcome          AckOutcome `json:"outcome"`
	EvidenceDigest   string     `json:"evidence_digest"`
	ProvenanceDigest string     `json:"provenance_digest"`
}

type CapabilityProfile struct {
	CapabilityDigest         string   `json:"capability_digest"`
	QualificationDigest      string   `json:"qualification_digest"`
	DataRoute                string   `json:"data_route"`
	StateMode                string   `json:"state_mode"`
	MessageRoles             []string `json:"message_roles"`
	ContentKinds             []string `json:"content_kinds"`
	StateModes               []string `json:"state_modes"`
	ToolCalls                bool     `json:"tool_calls"`
	StructuredOutput         bool     `json:"structured_output"`
	Streaming                bool     `json:"streaming"`
	Cancellation             bool     `json:"cancellation"`
	Usage                    bool     `json:"usage"`
	MaximumInputTokens       uint64   `json:"maximum_input_tokens"`
	MaximumOutputTokens      uint64   `json:"maximum_output_tokens"`
	MaximumMessages          uint32   `json:"maximum_messages"`
	MaximumTools             uint16   `json:"maximum_tools"`
	MaximumParallelToolCalls uint16   `json:"maximum_parallel_tool_calls"`
	MaximumStreamSeconds     uint32   `json:"maximum_stream_seconds"`
	ContextLimit             uint64   `json:"context_limit"`
}

type RouteBinding struct {
	DecisionID     string            `json:"decision_id"`
	PolicyDigest   string            `json:"policy_digest"`
	RequestedRoute string            `json:"requested_route"`
	PrimaryRoute   string            `json:"primary_route"`
	FallbackRoute  string            `json:"fallback_route"`
	ApprovalDigest string            `json:"approval_digest"`
	Primary        CapabilityProfile `json:"primary"`
	Fallback       CapabilityProfile `json:"fallback"`
	IssuedAt       time.Time         `json:"issued_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
}

type ProviderAttempt struct {
	Sequence         uint32             `json:"sequence"`
	AttemptID        string             `json:"attempt_id"`
	Route            string             `json:"route"`
	CapabilityDigest string             `json:"capability_digest"`
	Status           Status             `json:"status"`
	Outcome          string             `json:"outcome"`
	Artifact         domain.ArtifactRef `json:"artifact"`
	EvidenceDigest   string             `json:"evidence_digest"`
}

type Record struct {
	SchemaVersion            string             `json:"schema_version"`
	ContractVersion          string             `json:"contract_version"`
	ControlID                string             `json:"control_id"`
	Kind                     Kind               `json:"kind"`
	Case                     domain.CaseRef     `json:"case"`
	RunID                    string             `json:"run_id"`
	TaskID                   string             `json:"task_id"`
	PolicyDigest             string             `json:"policy_digest"`
	IntentDigest             string             `json:"intent_digest"`
	IdempotencyDigest        string             `json:"idempotency_digest"`
	ExpectedProvenanceDigest string             `json:"expected_provenance_digest"`
	ReasonDigest             string             `json:"reason_digest"`
	Operation                domain.Operation   `json:"operation"`
	InputRefs                []string           `json:"input_refs"`
	BudgetReservationDigest  string             `json:"budget_reservation_digest"`
	ObservedWork             WorkSnapshot       `json:"observed_work"`
	ResultWork               WorkSnapshot       `json:"result_work"`
	Targets                  []CancelTarget     `json:"targets"`
	Acknowledgments          []CancellationAck  `json:"acknowledgments"`
	Route                    RouteBinding       `json:"route"`
	Attempts                 []ProviderAttempt  `json:"attempts"`
	ResultArtifact           domain.ArtifactRef `json:"result_artifact"`
	Status                   Status             `json:"status"`
	ReasonCode               string             `json:"reason_code"`
	PreviousProvenanceDigest string             `json:"previous_provenance_digest"`
	ProvenanceDigest         string             `json:"provenance_digest"`
	CreatedAt                time.Time          `json:"created_at"`
	Deadline                 time.Time          `json:"deadline"`
	UpdatedAt                time.Time          `json:"updated_at"`
	Revision                 uint64             `json:"revision"`
}

type RecoverRequest struct {
	IdempotencyKey           string
	ControlID                string
	Case                     domain.CaseRef
	RunID                    string
	TaskID                   string
	PolicyDigest             string
	ExpectedProvenanceDigest string
	IntentDigest             string
	CreatedAt                time.Time
	Deadline                 time.Time
}

type CancelRequest struct {
	IdempotencyKey           string
	ControlID                string
	Case                     domain.CaseRef
	RunID                    string
	TaskID                   string
	PolicyDigest             string
	ExpectedProvenanceDigest string
	ReasonDigest             string
	Targets                  []CancelTarget
	CreatedAt                time.Time
	Deadline                 time.Time
}

type InvokeRequest struct {
	IdempotencyKey          string
	ControlID               string
	Case                    domain.CaseRef
	RunID                   string
	TaskID                  string
	PolicyDigest            string
	RequestedRoute          string
	Operation               domain.Operation
	InputRefs               []string
	BudgetReservationDigest string
	CreatedAt               time.Time
	Deadline                time.Time
}

type Result struct {
	ControlID        string
	Kind             Kind
	Status           Status
	Work             WorkSnapshot
	Acknowledgments  []CancellationAck
	Route            RouteBinding
	Attempts         []ProviderAttempt
	Artifact         domain.ArtifactRef
	ProvenanceDigest string
	Replayed         bool
}

type WorkLookup struct {
	Case   domain.CaseRef
	RunID  string
	TaskID string
}

type WorkResume struct {
	IdempotencyKey           string
	Case                     domain.CaseRef
	RunID                    string
	TaskID                   string
	ExpectedProvenanceDigest string
	IntentDigest             string
}

type WorkCoordinator interface {
	Inspect(context.Context, WorkLookup) (WorkSnapshot, error)
	Resume(context.Context, WorkResume) (WorkSnapshot, error)
}

type CancelCommand struct {
	IdempotencyKey string
	Case           domain.CaseRef
	RunID          string
	RootTaskID     string
	Target         CancelTarget
	ReasonDigest   string
	Deadline       time.Time
}

type ChildTaskCanceler interface {
	CancelChild(context.Context, CancelCommand) (CancellationAck, error)
}

type ToolJobCanceler interface {
	CancelJob(context.Context, CancelCommand) (CancellationAck, error)
}

type RouteApprovalRequest struct {
	Case                    domain.CaseRef
	RunID                   string
	TaskID                  string
	PolicyDigest            string
	RequestedRoute          string
	Operation               domain.Operation
	InputRefs               []string
	BudgetReservationDigest string
	CreatedAt               time.Time
	Deadline                time.Time
}

type ApprovedRoute struct {
	DecisionID            string
	PolicyDigest          string
	RequestedRoute        string
	PrimaryRoute          string
	FallbackRoute         string
	ApprovalDigest        string
	PrimaryCapability     providercontract.ValidatedCapability
	PrimaryQualification  providercontract.ValidatedQualification
	FallbackCapability    providercontract.ValidatedCapability
	FallbackQualification providercontract.ValidatedQualification
	IssuedAt              time.Time
	ExpiresAt             time.Time
}

type RouteAuthority interface {
	ApproveFallback(context.Context, RouteApprovalRequest) (ApprovedRoute, error)
}

type AttemptRequest struct {
	AttemptID        string
	Route            string
	CapabilityDigest string
	Operation        domain.Operation
	InputRefs        []string
	Deadline         time.Time
}

type AttemptReceipt struct {
	AttemptID        string
	Route            string
	CapabilityDigest string
	Outcome          string
	Artifact         domain.ArtifactRef
	EvidenceDigest   string
}

type ProviderInvoker interface {
	InvokeProvider(context.Context, AttemptRequest) (AttemptReceipt, error)
}

type Store interface {
	Load(context.Context, domain.CaseRef, string) (Record, bool, error)
	Begin(context.Context, string, Record) (Record, bool, error)
	Save(context.Context, string, Record, Record) (Record, error)
}

type Clock interface{ Now() time.Time }

type Control interface {
	Recover(context.Context, RecoverRequest) (Result, error)
	Cancel(context.Context, CancelRequest) (Result, error)
	Invoke(context.Context, InvokeRequest) (Result, error)
}
