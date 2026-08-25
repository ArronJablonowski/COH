package secretref

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type Decision struct {
	SchemaVersion    string  `json:"schema_version"`
	ContractVersion  string  `json:"contract_version"`
	DecisionDigest   string  `json:"decision_digest"`
	Outcome          string  `json:"outcome"`
	ReasonCode       string  `json:"reason_code"`
	RequestID        string  `json:"request_id,omitempty"`
	Context          Context `json:"context"`
	ActionDigest     string  `json:"action_digest,omitempty"`
	CredentialClass  string  `json:"credential_class,omitempty"`
	ReferenceDigest  string  `json:"reference_digest,omitempty"`
	Backend          string  `json:"backend,omitempty"`
	ReferenceVersion uint64  `json:"reference_version,omitempty"`
	ActorRevision    uint64  `json:"actor_revision,omitempty"`
	AuthorityDigest  string  `json:"authority_digest,omitempty"`
	RecordRevision   uint64  `json:"record_revision,omitempty"`
	Replayed         bool    `json:"replayed"`
}

func NewDecision(request ResolutionRequest, authority AuthoritySnapshot, outcome, reason string, recordRevision uint64, replayed bool) Decision {
	decision := Decision{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		Outcome: outcome, ReasonCode: reason, RecordRevision: recordRevision, Replayed: replayed,
	}
	if err := ValidateAuthority(authority); err == nil {
		decision.Context = authority.Context
		decision.ActorRevision = authority.ActorRevision
		decision.AuthorityDigest = authority.AuthorizationDecisionDigest
	}
	if err := ValidateResolutionRequest(request); err == nil {
		decision.RequestID = request.RequestID
		if decision.Context == (Context{}) {
			decision.Context = request.Context
		}
		decision.ActionDigest = request.ActionDigest
		decision.CredentialClass = request.CredentialClass
		referenceDigest, _ := ReferenceDigest(request.Reference)
		decision.ReferenceDigest = referenceDigest
		decision.Backend = request.Reference.Backend
		decision.ReferenceVersion = request.Reference.Version
	}
	return finalizeDecision(decision)
}

func RequestDigest(request ResolutionRequest) (string, error) {
	if err := ValidateResolutionRequest(request); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", secretError(InvalidInput, "resolution_encoding", nil)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func finalizeDecision(decision Decision) Decision {
	decision.DecisionDigest = ""
	encoded, err := json.Marshal(decision)
	if err != nil {
		panic("secret reference decision contains only JSON-safe fields")
	}
	sum := sha256.Sum256(encoded)
	decision.DecisionDigest = "sha256:" + hex.EncodeToString(sum[:])
	return decision
}
