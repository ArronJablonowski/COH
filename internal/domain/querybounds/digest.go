package querybounds

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	authorityDigestDomain = "COH-QUERY-BOUND-AUTHORITY-V1\x00"
	resourceDigestDomain  = "COH-QUERY-BOUND-RESOURCES-V1\x00"
	limitsDigestDomain    = "COH-QUERY-BOUND-LIMITS-V1\x00"
)

type canonicalAuthority struct {
	OrganizationID              string                `json:"organization_id"`
	TenantID                    string                `json:"tenant_id"`
	CaseID                      string                `json:"case_id"`
	ActorID                     string                `json:"actor_id"`
	ActorRevision               uint64                `json:"actor_revision"`
	ActorActive                 bool                  `json:"actor_active"`
	SourceID                    string                `json:"source_id"`
	SourceRevision              uint64                `json:"source_revision"`
	SourceActive                bool                  `json:"source_active"`
	ResourceIDs                 []string              `json:"resource_ids"`
	AllowlistRevision           uint64                `json:"allowlist_revision"`
	AllowlistActive             bool                  `json:"allowlist_active"`
	CapabilityDigest            string                `json:"capability_digest"`
	CapabilityRevision          uint64                `json:"capability_revision"`
	CapabilityActive            bool                  `json:"capability_active"`
	AuthorizationAllowed        bool                  `json:"authorization_allowed"`
	AuthorizationDecisionDigest string                `json:"authorization_decision_digest"`
	PolicyAllowed               bool                  `json:"policy_allowed"`
	PolicyDecisionDigest        string                `json:"policy_decision_digest"`
	PolicyRevision              uint64                `json:"policy_revision"`
	ApprovalRequired            bool                  `json:"approval_required"`
	ApprovalAllowed             bool                  `json:"approval_allowed"`
	ApprovalDecisionDigest      string                `json:"approval_decision_digest"`
	ApprovalQueryDigest         string                `json:"approval_query_digest"`
	ApprovalPolicyDigest        string                `json:"approval_policy_digest"`
	ApprovalExpiresAt           string                `json:"approval_expires_at"`
	AuditReservationDigest      string                `json:"audit_reservation_digest"`
	EmergencyStopActive         bool                  `json:"emergency_stop_active"`
	RevocationRevision          uint64                `json:"revocation_revision"`
	MaximumIntervalNanos        int64                 `json:"maximum_interval_nanos"`
	MaximumFutureSkewNanos      int64                 `json:"maximum_future_skew_nanos"`
	MaximumLimits               queryconnector.Limits `json:"maximum_limits"`
	ObservedAt                  string                `json:"observed_at"`
}

func authorityDigest(value AuthoritySnapshot) (string, error) {
	expires := ""
	if !value.ApprovalExpiresAt.IsZero() {
		expires = formatTime(value.ApprovalExpiresAt)
	}
	record := canonicalAuthority{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID,
		ActorID: value.ActorID, ActorRevision: value.ActorRevision, ActorActive: value.ActorActive,
		SourceID: value.SourceID, SourceRevision: value.SourceRevision, SourceActive: value.SourceActive,
		ResourceIDs: append([]string(nil), value.ResourceIDs...), AllowlistRevision: value.AllowlistRevision, AllowlistActive: value.AllowlistActive,
		CapabilityDigest: value.CapabilityDigest, CapabilityRevision: value.CapabilityRevision, CapabilityActive: value.CapabilityActive,
		AuthorizationAllowed: value.AuthorizationAllowed, AuthorizationDecisionDigest: value.AuthorizationDecisionDigest,
		PolicyAllowed: value.PolicyAllowed, PolicyDecisionDigest: value.PolicyDecisionDigest, PolicyRevision: value.PolicyRevision,
		ApprovalRequired: value.ApprovalRequired, ApprovalAllowed: value.ApprovalAllowed,
		ApprovalDecisionDigest: value.ApprovalDecisionDigest, ApprovalQueryDigest: value.ApprovalQueryDigest,
		ApprovalPolicyDigest: value.ApprovalPolicyDecisionDigest, ApprovalExpiresAt: expires,
		AuditReservationDigest: value.AuditReservationDigest, EmergencyStopActive: value.EmergencyStopActive,
		RevocationRevision: value.RevocationRevision, MaximumIntervalNanos: value.MaximumInterval.Nanoseconds(),
		MaximumFutureSkewNanos: value.MaximumFutureSkew.Nanoseconds(), MaximumLimits: value.MaximumLimits,
		ObservedAt: formatTime(value.ObservedAt)}
	return digestValue(authorityDigestDomain, record)
}

func resourceDigest(scope queryconnector.Scope) (string, error) {
	return digestValue(resourceDigestDomain, struct {
		OrganizationID string   `json:"organization_id"`
		TenantID       string   `json:"tenant_id"`
		CaseID         string   `json:"case_id"`
		SourceID       string   `json:"source_id"`
		ResourceIDs    []string `json:"resource_ids"`
	}{scope.OrganizationID, scope.TenantID, scope.CaseID, scope.SourceID, append([]string(nil), scope.ResourceIDs...)})
}

func limitsDigest(value queryconnector.Limits) (string, error) {
	return digestValue(limitsDigestDomain, value)
}

func digestValue(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func formatTime(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05.000000000Z") }
