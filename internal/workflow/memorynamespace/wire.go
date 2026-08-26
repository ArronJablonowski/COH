package memorynamespace

import "github.com/ArronJablonowski/COH/internal/domain"

type artifactWire struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type retentionWire struct {
	Class        string `json:"class"`
	PolicyDigest string `json:"policy_digest"`
	ExpiresAt    string `json:"expires_at"`
}

type reviewWire struct {
	ReviewID        string `json:"review_id"`
	ReviewerActorID string `json:"reviewer_actor_id"`
	Revision        uint64 `json:"revision"`
	AuthorityDigest string `json:"authority_digest"`
	ReviewedAt      string `json:"reviewed_at"`
	ValidUntil      string `json:"valid_until"`
}

type recordWire struct {
	SchemaVersion            string        `json:"schema_version"`
	ContractVersion          string        `json:"contract_version"`
	Namespace                Namespace     `json:"namespace"`
	Scope                    Scope         `json:"scope"`
	Key                      string        `json:"key"`
	Value                    artifactWire  `json:"value"`
	ValueType                string        `json:"value_type"`
	Retention                retentionWire `json:"retention"`
	Review                   reviewWire    `json:"review"`
	WriterActorID            string        `json:"writer_actor_id"`
	PolicyDigest             string        `json:"policy_digest"`
	IntentDigest             string        `json:"intent_digest"`
	IdempotencyDigest        string        `json:"idempotency_digest"`
	AccessDecisionDigest     string        `json:"access_decision_digest"`
	ReviewDecisionDigest     string        `json:"review_decision_digest"`
	PreviousProvenanceDigest string        `json:"previous_provenance_digest"`
	ProvenanceDigest         string        `json:"provenance_digest"`
	CreatedAt                string        `json:"created_at"`
	UpdatedAt                string        `json:"updated_at"`
	Revision                 uint64        `json:"revision"`
}

type accessRequestWire struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	RequestID       string    `json:"request_id"`
	ActorID         string    `json:"actor_id"`
	Operation       Operation `json:"operation"`
	Namespace       Namespace `json:"namespace"`
	Scope           Scope     `json:"scope"`
	Key             string    `json:"key"`
	ValueDigest     string    `json:"value_digest"`
	RetentionDigest string    `json:"retention_digest"`
	PolicyDigest    string    `json:"policy_digest"`
	Deadline        string    `json:"deadline"`
}

type decisionWireType struct {
	SchemaVersion       string `json:"schema_version"`
	ContractVersion     string `json:"contract_version"`
	Allowed             bool   `json:"allowed"`
	ReasonCode          string `json:"reason_code"`
	AccessRequestDigest string `json:"access_request_digest"`
	DecisionDigest      string `json:"decision_digest"`
	DecidedAt           string `json:"decided_at"`
	ExpiresAt           string `json:"expires_at"`
}

type reviewRequestWireType struct {
	SchemaVersion   string     `json:"schema_version"`
	ContractVersion string     `json:"contract_version"`
	RequestID       string     `json:"request_id"`
	ActorID         string     `json:"actor_id"`
	WriterActorID   string     `json:"writer_actor_id"`
	Operation       Operation  `json:"operation"`
	Scope           Scope      `json:"scope"`
	Key             string     `json:"key"`
	ValueDigest     string     `json:"value_digest"`
	Review          reviewWire `json:"review"`
	PolicyDigest    string     `json:"policy_digest"`
	Deadline        string     `json:"deadline"`
}

type reviewDecisionWireType struct {
	SchemaVersion       string `json:"schema_version"`
	ContractVersion     string `json:"contract_version"`
	Allowed             bool   `json:"allowed"`
	ReasonCode          string `json:"reason_code"`
	ReviewRequestDigest string `json:"review_request_digest"`
	DecisionDigest      string `json:"decision_digest"`
	DecidedAt           string `json:"decided_at"`
	ExpiresAt           string `json:"expires_at"`
}

func artifactToWire(v domain.ArtifactRef) artifactWire {
	return artifactWire{v.Digest, v.MediaType, v.Classification, v.Length}
}
func retentionToWire(v RetentionPolicy) retentionWire {
	return retentionWire{v.Class, v.PolicyDigest, formatTime(v.ExpiresAt)}
}
func reviewToWire(v Review) reviewWire {
	return reviewWire{v.ReviewID, v.ReviewerActorID, v.Revision, v.AuthorityDigest, formatTime(v.ReviewedAt), formatTime(v.ValidUntil)}
}
func recordToWire(v Record) recordWire {
	return recordWire{v.SchemaVersion, v.ContractVersion, v.Namespace, v.Scope, v.Key, artifactToWire(v.Value), v.ValueType, retentionToWire(v.Retention), reviewToWire(v.Review), v.WriterActorID, v.PolicyDigest, v.IntentDigest, v.IdempotencyDigest, v.AccessDecisionDigest, v.ReviewDecisionDigest, v.PreviousProvenanceDigest, v.ProvenanceDigest, formatTime(v.CreatedAt), formatTime(v.UpdatedAt), v.Revision}
}
func accessWire(v AccessRequest) accessRequestWire {
	return accessRequestWire{v.SchemaVersion, v.ContractVersion, v.RequestID, v.ActorID, v.Operation, v.Namespace, v.Scope, v.Key, v.ValueDigest, v.RetentionDigest, v.PolicyDigest, formatTime(v.Deadline)}
}
func decisionWire(v Decision) decisionWireType {
	return decisionWireType{v.SchemaVersion, v.ContractVersion, v.Allowed, v.ReasonCode, v.AccessRequestDigest, v.DecisionDigest, formatTime(v.DecidedAt), formatTime(v.ExpiresAt)}
}
func reviewRequestWire(v ReviewRequest) reviewRequestWireType {
	return reviewRequestWireType{v.SchemaVersion, v.ContractVersion, v.RequestID, v.ActorID, v.WriterActorID, v.Operation, v.Scope, v.Key, v.ValueDigest, reviewToWire(v.Review), v.PolicyDigest, formatTime(v.Deadline)}
}
func reviewDecisionWire(v ReviewDecision) reviewDecisionWireType {
	return reviewDecisionWireType{v.SchemaVersion, v.ContractVersion, v.Allowed, v.ReasonCode, v.ReviewRequestDigest, v.DecisionDigest, formatTime(v.DecidedAt), formatTime(v.ExpiresAt)}
}
