// Package localidentity defines local actor identity and scoped RBAC semantics.
// Cryptographic login, session storage, and audit composition live at the
// authenticated transport boundary; this package owns only immutable types and
// deterministic authorization decisions.
package localidentity

const (
	SchemaVersion   = "coh.local-identity/v1"
	ContractVersion = "1.0.0"
)

type Role string

const (
	Analyst       Role = "analyst"
	Approver      Role = "approver"
	Administrator Role = "administrator"
	Auditor       Role = "auditor"
	Service       Role = "service"
)

type Permission string

const (
	CaseRead            Permission = "case.read"
	CaseWrite           Permission = "case.write"
	EvidenceRead        Permission = "evidence.read"
	EvidenceWrite       Permission = "evidence.write"
	QueryExecute        Permission = "query.execute"
	WorkflowManage      Permission = "workflow.manage"
	ActionRequest       Permission = "action.request"
	ApprovalDecide      Permission = "approval.decide"
	ConfigurationManage Permission = "configuration.manage"
	IdentityManage      Permission = "identity.manage"
	AuditRead           Permission = "audit.read"
	ServiceInvoke       Permission = "service.invoke"
)

type ActionTier string

const (
	T0 ActionTier = "T0"
	T1 ActionTier = "T1"
	T2 ActionTier = "T2"
	T3 ActionTier = "T3"
	T4 ActionTier = "T4"
)

type Channel string

const (
	API Channel = "api"
	CLI Channel = "cli"
)

type Actor struct {
	SchemaVersion   string       `json:"schema_version"`
	ContractVersion string       `json:"contract_version"`
	ID              string       `json:"id"`
	OrganizationID  string       `json:"organization_id"`
	Name            string       `json:"name"`
	Roles           []Role       `json:"roles"`
	Grants          []ScopeGrant `json:"grants"`
	PublicKey       string       `json:"public_key"`
	Revision        uint64       `json:"revision"`
	Active          bool         `json:"active"`
}

type ScopeGrant struct {
	TenantID string   `json:"tenant_id"`
	AllCases bool     `json:"all_cases"`
	CaseIDs  []string `json:"case_ids"`
}

type Request struct {
	SchemaVersion   string     `json:"schema_version"`
	ContractVersion string     `json:"contract_version"`
	RequestID       string     `json:"request_id"`
	IdempotencyKey  string     `json:"idempotency_key"`
	PayloadDigest   string     `json:"payload_digest"`
	Channel         Channel    `json:"channel"`
	Context         Context    `json:"context"`
	Permission      Permission `json:"permission"`
	ActionTier      ActionTier `json:"action_tier"`
}

type Context struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
	ActorID        string `json:"actor_id"`
}

// Decision is safe audit input. It contains no public key, signature, session
// token, credential, request body, or backend error.
type Decision struct {
	SchemaVersion   string     `json:"schema_version"`
	ContractVersion string     `json:"contract_version"`
	DecisionDigest  string     `json:"decision_digest"`
	Outcome         string     `json:"outcome"`
	ReasonCode      string     `json:"reason_code"`
	RequestID       string     `json:"request_id,omitempty"`
	PayloadDigest   string     `json:"payload_digest,omitempty"`
	Channel         Channel    `json:"channel,omitempty"`
	Context         Context    `json:"context"`
	Permission      Permission `json:"permission,omitempty"`
	ActionTier      ActionTier `json:"action_tier,omitempty"`
	ActorRevision   uint64     `json:"actor_revision,omitempty"`
	SessionID       string     `json:"session_id,omitempty"`
	Replayed        bool       `json:"replayed"`
}
