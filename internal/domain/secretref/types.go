// Package secretref defines opaque credential references and the scoped
// broker-resolution request contract. It contains no secret value type.
package secretref

const (
	SchemaVersion   = "coh.secret-reference/v1"
	ContractVersion = "1.0.0"
)

type Reference struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	Backend         string `json:"backend"`
	EntryID         string `json:"entry_id"`
	Version         uint64 `json:"version"`
}

type ResolutionRequest struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	RequestID       string    `json:"request_id"`
	IdempotencyKey  string    `json:"idempotency_key"`
	Context         Context   `json:"context"`
	ActionDigest    string    `json:"action_digest"`
	CredentialClass string    `json:"credential_class"`
	Reference       Reference `json:"reference"`
}

type Context struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
	ActorID        string `json:"actor_id"`
}

// AuthoritySnapshot is supplied by the authenticated broker boundary. Secret
// resolution binds to it but does not manufacture authentication authority.
type AuthoritySnapshot struct {
	Context                     Context
	Active                      bool
	ActorRevision               uint64
	AuthorizationDecisionDigest string
}
