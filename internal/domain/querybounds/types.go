package querybounds

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	ContractVersion       = "1.0.0"
	DecisionSchemaVersion = "coh.query-bound-decision/v1"
	MaximumAuthorityAge   = 30 * time.Second
)

// AuthoritySnapshot is fresh trusted broker input. Query data cannot assert
// or widen any field in this value.
type AuthoritySnapshot struct {
	OrganizationID              string
	TenantID                    string
	CaseID                      string
	ActorID                     string
	ActorRevision               uint64
	ActorActive                 bool
	SourceID                    string
	SourceRevision              uint64
	SourceActive                bool
	ResourceIDs                 []string
	AllowlistRevision           uint64
	CapabilityDigest            string
	CapabilityRevision          uint64
	CapabilityActive            bool
	AuthorizationAllowed        bool
	AuthorizationDecisionDigest string
	PolicyAllowed               bool
	PolicyDecisionDigest        string
	PolicyRevision              uint64
	ApprovalRequired            bool
	ApprovalAllowed             bool
	ApprovalDecisionDigest      string
	ApprovalExpiresAt           time.Time
	AuditReservationDigest      string
	EmergencyStopActive         bool
	RevocationRevision          uint64
	MaximumInterval             time.Duration
	MaximumFutureSkew           time.Duration
	MaximumLimits               queryconnector.Limits
	ObservedAt                  time.Time
}

// Decision is redacted audit and evidence input. Native query text, result
// rows, credentials, vendor handles, and raw dependency errors have no field.
type Decision struct {
	SchemaVersion               string `json:"schema_version"`
	ContractVersion             string `json:"contract_version"`
	DecisionDigest              string `json:"decision_digest"`
	QueryID                     string `json:"query_id"`
	QueryDigest                 string `json:"query_digest"`
	Outcome                     string `json:"outcome"`
	ReasonCode                  string `json:"reason_code"`
	OrganizationID              string `json:"organization_id"`
	TenantID                    string `json:"tenant_id"`
	CaseID                      string `json:"case_id"`
	ActorID                     string `json:"actor_id"`
	ActorRevision               uint64 `json:"actor_revision"`
	SourceID                    string `json:"source_id"`
	SourceRevision              uint64 `json:"source_revision"`
	AllowlistRevision           uint64 `json:"allowlist_revision"`
	CapabilityDigest            string `json:"capability_digest"`
	CapabilityRevision          uint64 `json:"capability_revision"`
	AuthorityDigest             string `json:"authority_digest"`
	ResourceScopeDigest         string `json:"resource_scope_digest"`
	AuthorizationDecisionDigest string `json:"authorization_decision_digest"`
	PolicyDecisionDigest        string `json:"policy_decision_digest"`
	PolicyRevision              uint64 `json:"policy_revision"`
	ApprovalDecisionDigest      string `json:"approval_decision_digest,omitempty"`
	ApprovalRequired            bool   `json:"approval_required"`
	AuditReservationDigest      string `json:"audit_reservation_digest"`
	RevocationRevision          uint64 `json:"revocation_revision"`
	IntervalStart               string `json:"interval_start"`
	IntervalEnd                 string `json:"interval_end"`
	LimitsDigest                string `json:"limits_digest"`
	EvaluatedAt                 string `json:"evaluated_at"`
	Replayed                    bool   `json:"replayed"`
}

type Admission struct {
	Query    queryconnector.ValidatedQuery
	Decision Decision
}

// AuditSink must durably accept every redacted decision before an allowed
// admission can be returned.
type AuditSink interface {
	AppendQueryBoundDecision(context.Context, Decision) error
}

type Clock interface {
	Now() time.Time
}

// ReplayGuard identifies exact replay and rejects changed use of a query ID.
// It supplies no authority; the engine always rechecks fresh authority first.
type ReplayGuard interface {
	Observe(context.Context, string, string) (exactReplay bool, err error)
}
