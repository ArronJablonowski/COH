// Package estop defines canonical global and case-scoped emergency-stop
// commands, state, control acknowledgements, and redacted decisions.
package estop

import "time"

const (
	ContractVersion         = "1.0.0"
	CommandSchemaVersion    = "coh.estop-command/v1"
	StateSchemaVersion      = "coh.estop-state/v1"
	AckSchemaVersion        = "coh.estop-control-ack/v1"
	DecisionSchemaVersion   = "coh.estop-decision/v1"
	MaximumInputBytes       = 32 << 10
	MaximumAuthorityAge     = 30 * time.Second
	LeaseRejectObjective    = time.Second
	EgressCutObjective      = 2 * time.Second
	WorkflowSignalObjective = 5 * time.Second
	TerminationObjective    = 10 * time.Second
)

type Scope struct {
	Kind           string `json:"kind"`
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id,omitempty"`
}

type Command struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	RequestID       string `json:"request_id"`
	IdempotencyKey  string `json:"idempotency_key"`
	Scope           Scope  `json:"scope"`
	ActorID         string `json:"actor_id"`
	ReasonCode      string `json:"reason_code"`
}

// Authority is trusted authenticated control-plane input. Command data cannot
// assert or modify these facts.
type Authority struct {
	Scope                       Scope
	ActorID                     string
	ActorRevision               uint64
	ActorActive                 bool
	AuthorizationAllowed        bool
	AuthorizationDecisionDigest string
	PolicyAllowed               bool
	PolicyDecisionDigest        string
	ObservedAt                  time.Time
}

type State struct {
	SchemaVersion               string    `json:"schema_version"`
	ContractVersion             string    `json:"contract_version"`
	Scope                       Scope     `json:"scope"`
	Epoch                       uint64    `json:"epoch"`
	Active                      bool      `json:"active"`
	RequestID                   string    `json:"request_id"`
	RequestDigest               string    `json:"request_digest"`
	ActorID                     string    `json:"actor_id"`
	ActorRevision               uint64    `json:"actor_revision"`
	ReasonCode                  string    `json:"reason_code"`
	AuthorizationDecisionDigest string    `json:"authorization_decision_digest"`
	PolicyDecisionDigest        string    `json:"policy_decision_digest"`
	ActivatedAt                 time.Time `json:"activated_at"`
}

type ControlRequest struct {
	Scope       Scope
	Epoch       uint64
	ActivatedAt time.Time
}

type Acknowledgement struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	Scope           Scope     `json:"scope"`
	Epoch           uint64    `json:"epoch"`
	ControlID       string    `json:"control_id"`
	ControlKind     string    `json:"control_kind"`
	Outcome         string    `json:"outcome"`
	ReasonCode      string    `json:"reason_code"`
	EvidenceDigest  string    `json:"evidence_digest,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at"`
	ElapsedNanos    int64     `json:"elapsed_nanos"`
	ObjectiveNanos  int64     `json:"objective_nanos"`
}

type Result struct {
	State            State
	Acknowledgements []Acknowledgement
	AuditPending     bool
}

type Decision struct {
	SchemaVersion               string    `json:"schema_version"`
	ContractVersion             string    `json:"contract_version"`
	Event                       string    `json:"event"`
	Outcome                     string    `json:"outcome"`
	ReasonCode                  string    `json:"reason_code"`
	RequestID                   string    `json:"request_id,omitempty"`
	Scope                       Scope     `json:"scope"`
	Epoch                       uint64    `json:"epoch,omitempty"`
	ActorID                     string    `json:"actor_id,omitempty"`
	ActorRevision               uint64    `json:"actor_revision,omitempty"`
	ControlID                   string    `json:"control_id,omitempty"`
	ControlKind                 string    `json:"control_kind,omitempty"`
	ControlOutcome              string    `json:"control_outcome,omitempty"`
	EvidenceDigest              string    `json:"evidence_digest,omitempty"`
	AuthorizationDecisionDigest string    `json:"authorization_decision_digest,omitempty"`
	PolicyDecisionDigest        string    `json:"policy_decision_digest,omitempty"`
	ActivatedAt                 time.Time `json:"activated_at,omitempty"`
	OccurredAt                  time.Time `json:"occurred_at"`
	ElapsedNanos                int64     `json:"elapsed_nanos,omitempty"`
	ObjectiveNanos              int64     `json:"objective_nanos,omitempty"`
	DecisionDigest              string    `json:"decision_digest"`
}

type AuditRecord struct {
	ID        string
	Decision  Decision
	Delivered bool
}
