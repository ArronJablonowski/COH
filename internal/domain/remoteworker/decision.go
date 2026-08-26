package remoteworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Decision struct {
	SchemaVersion               string    `json:"schema_version"`
	ContractVersion             string    `json:"contract_version"`
	Event                       string    `json:"event"`
	Outcome                     string    `json:"outcome"`
	ReasonCode                  string    `json:"reason_code"`
	RequestID                   string    `json:"request_id,omitempty"`
	LeaseID                     string    `json:"lease_id,omitempty"`
	OrganizationID              string    `json:"organization_id,omitempty"`
	TenantID                    string    `json:"tenant_id,omitempty"`
	CaseID                      string    `json:"case_id,omitempty"`
	ActorID                     string    `json:"actor_id,omitempty"`
	ActorRevision               uint64    `json:"actor_revision,omitempty"`
	TaskID                      string    `json:"task_id,omitempty"`
	ActionDigest                string    `json:"action_digest,omitempty"`
	TargetScopeDigest           string    `json:"target_scope_digest,omitempty"`
	ToolDigest                  string    `json:"tool_digest,omitempty"`
	Operation                   string    `json:"operation,omitempty"`
	RequiredTier                string    `json:"required_tier,omitempty"`
	IsolationClass              string    `json:"isolation_class,omitempty"`
	WorkerID                    string    `json:"worker_id,omitempty"`
	WorkerRevision              uint64    `json:"worker_revision,omitempty"`
	TransportIdentityDigest     string    `json:"transport_identity_digest,omitempty"`
	CertificateFingerprint      string    `json:"certificate_fingerprint,omitempty"`
	CertificateRevision         uint64    `json:"certificate_revision,omitempty"`
	AttestationDigest           string    `json:"attestation_digest,omitempty"`
	AttestationKeyRevision      uint64    `json:"attestation_key_revision,omitempty"`
	AttestationKeyDigest        string    `json:"attestation_key_digest,omitempty"`
	AuthorizationDecisionDigest string    `json:"authorization_decision_digest,omitempty"`
	PolicyDecisionDigest        string    `json:"policy_decision_digest,omitempty"`
	ApprovalDecisionDigest      string    `json:"approval_decision_digest,omitempty"`
	IssuedAt                    time.Time `json:"issued_at,omitempty"`
	ExpiresAt                   time.Time `json:"expires_at,omitempty"`
	OccurredAt                  time.Time `json:"occurred_at"`
	DecisionDigest              string    `json:"decision_digest"`
}

func FinalizeDecision(decision Decision) Decision {
	decision.SchemaVersion = DecisionSchemaVersion
	decision.ContractVersion = ContractVersion
	decision.DecisionDigest = ""
	encoded, _ := json.Marshal(decision)
	sum := sha256.Sum256(encoded)
	decision.DecisionDigest = "sha256:" + hex.EncodeToString(sum[:])
	return decision
}

func TargetScopeDigest(targets []string) string {
	encoded, _ := json.Marshal(targets)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func EnrollmentRequestDigest(request EnrollmentRequest) (string, error) {
	if err := ValidateEnrollmentRequest(request); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", NewError(InvalidInput, "enrollment_encoding")
	}
	canonical, err := canonicalBytes(encoded)
	if err != nil {
		return "", err
	}
	return hashBytes(canonical), nil
}

func LeaseRequestDigest(request LeaseRequest) (string, error) {
	if err := ValidateLeaseRequest(request); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", NewError(InvalidInput, "lease_encoding")
	}
	canonical, err := canonicalBytes(encoded)
	if err != nil {
		return "", err
	}
	return hashBytes(canonical), nil
}

func canonicalBytes(input []byte) ([]byte, error) {
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		return nil, NewError(InvalidInput, "contract_encoding")
	}
	return json.Marshal(value)
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
