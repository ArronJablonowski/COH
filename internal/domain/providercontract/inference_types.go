package providercontract

import "encoding/json"

type ContentItem struct {
	Kind               string          `json:"kind"`
	Text               string          `json:"text,omitempty"`
	Value              json.RawMessage `json:"value,omitempty"`
	SchemaDigest       string          `json:"schema_digest,omitempty"`
	CallID             string          `json:"call_id,omitempty"`
	ToolName           string          `json:"tool_name,omitempty"`
	Arguments          json.RawMessage `json:"arguments,omitempty"`
	InputSchemaDigest  string          `json:"input_schema_digest,omitempty"`
	Outcome            string          `json:"outcome,omitempty"`
	OutputSchemaDigest string          `json:"output_schema_digest,omitempty"`
	ResultDigest       string          `json:"result_digest,omitempty"`
	ReferenceID        string          `json:"reference_id,omitempty"`
	Digest             string          `json:"digest,omitempty"`
}

type Message struct {
	MessageID string        `json:"message_id"`
	Role      string        `json:"role"`
	Items     []ContentItem `json:"items"`
}

type Tool struct {
	Name               string `json:"name"`
	Description        string `json:"description"`
	InputSchemaDigest  string `json:"input_schema_digest"`
	OutputSchemaDigest string `json:"output_schema_digest"`
}

type OutputConstraint struct {
	Kind         string `json:"kind"`
	Name         string `json:"name,omitempty"`
	SchemaDigest string `json:"schema_digest,omitempty"`
	Strict       *bool  `json:"strict,omitempty"`
}

type Sampling struct {
	TemperatureMilli uint32 `json:"temperature_milli"`
	TopPMillionths   uint32 `json:"top_p_millionths"`
	Seed             uint32 `json:"seed"`
}

type State struct {
	Mode        string `json:"mode"`
	ReferenceID string `json:"reference_id,omitempty"`
	StateDigest string `json:"state_digest,omitempty"`
}

type InferenceRequest struct {
	SchemaVersion          string           `json:"schema_version"`
	ContractVersion        string           `json:"contract_version"`
	RequestID              string           `json:"request_id"`
	AttemptID              string           `json:"attempt_id"`
	OrganizationID         string           `json:"organization_id"`
	TenantID               string           `json:"tenant_id"`
	CaseID                 string           `json:"case_id"`
	TaskID                 string           `json:"task_id"`
	ActorID                string           `json:"actor_id"`
	Provider               ProviderIdentity `json:"provider"`
	CapabilityDigest       string           `json:"capability_digest"`
	QualificationID        string           `json:"qualification_id"`
	Messages               []Message        `json:"messages"`
	Tools                  []Tool           `json:"tools"`
	OutputConstraint       OutputConstraint `json:"output_constraint"`
	Sampling               Sampling         `json:"sampling"`
	MaximumOutputTokens    uint64           `json:"maximum_output_tokens"`
	State                  State            `json:"state"`
	Deadline               string           `json:"deadline"`
	AuthorizationDigest    string           `json:"authorization_digest"`
	PolicyDecisionDigest   string           `json:"policy_decision_digest"`
	ApprovalDecisionDigest string           `json:"approval_decision_digest"`
	AuditReservationDigest string           `json:"audit_reservation_digest"`
}

type Usage struct {
	InputTokens       uint64 `json:"input_tokens"`
	OutputTokens      uint64 `json:"output_tokens"`
	TotalTokens       uint64 `json:"total_tokens"`
	CachedInputTokens uint64 `json:"cached_input_tokens"`
	ReasoningTokens   uint64 `json:"reasoning_tokens"`
}

type TerminalError struct {
	Code      string `json:"code"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type InferenceResponse struct {
	SchemaVersion    string           `json:"schema_version"`
	ContractVersion  string           `json:"contract_version"`
	ResponseID       string           `json:"response_id"`
	RequestID        string           `json:"request_id"`
	AttemptID        string           `json:"attempt_id"`
	Provider         ProviderIdentity `json:"provider"`
	CapabilityDigest string           `json:"capability_digest"`
	QualificationID  string           `json:"qualification_id"`
	Outcome          string           `json:"outcome"`
	Items            []ContentItem    `json:"items"`
	Usage            Usage            `json:"usage"`
	State            State            `json:"state"`
	StartedAt        string           `json:"started_at"`
	CompletedAt      string           `json:"completed_at"`
	ProvenanceDigest string           `json:"provenance_digest"`
	Error            *TerminalError   `json:"error,omitempty"`
}

type UsageDelta struct {
	InputTokens       uint64 `json:"input_tokens"`
	OutputTokens      uint64 `json:"output_tokens"`
	CachedInputTokens uint64 `json:"cached_input_tokens"`
	ReasoningTokens   uint64 `json:"reasoning_tokens"`
}

type StreamEvent struct {
	SchemaVersion   string             `json:"schema_version"`
	ContractVersion string             `json:"contract_version"`
	RequestID       string             `json:"request_id"`
	AttemptID       string             `json:"attempt_id"`
	Sequence        uint64             `json:"sequence"`
	ObservedAt      string             `json:"observed_at"`
	Kind            string             `json:"kind"`
	TextDelta       string             `json:"text_delta,omitempty"`
	Item            *ContentItem       `json:"item,omitempty"`
	UsageDelta      *UsageDelta        `json:"usage_delta,omitempty"`
	Response        *InferenceResponse `json:"response,omitempty"`
	Error           *TerminalError     `json:"error,omitempty"`
}
