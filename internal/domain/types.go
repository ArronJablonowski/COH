// Package domain owns security-neutral business types and invariants.
//
// Domain code cannot depend on policy, orchestration, adapters, transports,
// commands, or UI code. Keep this package free of side effects.
package domain

// CaseRef is the minimum tenant-scoped identity carried across core ports.
// Richer domain contracts will replace this bootstrap type in COH-E03-01.
type CaseRef struct {
	OrganizationID string
	TenantID       string
	CaseID         string
}

// Operation identifies a bounded unit of work without carrying evidence,
// credentials, prompts, or large output through the orchestration boundary.
type Operation struct {
	ID      string
	Case    CaseRef
	Kind    string
	Version string
}

// ArtifactRef identifies immutable content without embedding the content.
type ArtifactRef struct {
	Digest         string
	MediaType      string
	Classification string
	Length         int64
}

// ToolIntent is the only action request accepted by the broker boundary. The
// argument and target digests bind exact canonical manifests defined later.
type ToolIntent struct {
	OperationID    string
	Case           CaseRef
	Tool           string
	Action         string
	TargetDigest   string
	ArgumentDigest string
}

// ActionReceipt records the broker-owned outcome without exposing credentials
// or mutable connector state to the workflow.
type ActionReceipt struct {
	IntentDigest string
	Outcome      string
	Evidence     ArtifactRef
}
