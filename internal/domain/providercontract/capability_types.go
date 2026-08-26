// Package providercontract owns the provider-neutral inference and
// qualification boundary. Vendor adapters must translate into these types.
package providercontract

const (
	ContractVersion            = "1.0.0"
	CapabilitySchemaVersion    = "coh.provider-capability/v1"
	RequestSchemaVersion       = "coh.provider-request/v1"
	ResponseSchemaVersion      = "coh.provider-response/v1"
	StreamEventSchemaVersion   = "coh.provider-stream-event/v1"
	QualificationSchemaVersion = "coh.provider-qualification/v1"
	MaximumInputBytes          = 1 << 20
)

type ProviderIdentity struct {
	ProviderKind           string `json:"provider_kind"`
	AdapterVersion         string `json:"adapter_version"`
	EndpointIdentityDigest string `json:"endpoint_identity_digest"`
	DataRoute              string `json:"data_route"`
	RequestedModel         string `json:"requested_model"`
	ActualModel            string `json:"actual_model"`
	ModelRevision          string `json:"model_revision"`
	RuntimeName            string `json:"runtime_name"`
	RuntimeVersion         string `json:"runtime_version"`
	RuntimeDigest          string `json:"runtime_digest"`
	TokenizerName          string `json:"tokenizer_name"`
	TokenizerVersion       string `json:"tokenizer_version"`
	TokenizerDigest        string `json:"tokenizer_digest"`
	ChatTemplateDigest     string `json:"chat_template_digest"`
	ToolParserDigest       string `json:"tool_parser_digest"`
	ReasoningParserDigest  string `json:"reasoning_parser_digest"`
	ContextLimit           uint64 `json:"context_limit"`
	SamplingProfileDigest  string `json:"sampling_profile_digest"`
	HardwareProfileDigest  string `json:"hardware_profile_digest"`
	StateMode              string `json:"state_mode"`
	PolicyRevision         uint64 `json:"policy_revision"`
}

type Features struct {
	MessageRoles     []string `json:"message_roles"`
	ContentKinds     []string `json:"content_kinds"`
	ToolCalls        bool     `json:"tool_calls"`
	StructuredOutput bool     `json:"structured_output"`
	Streaming        bool     `json:"streaming"`
	Cancellation     bool     `json:"cancellation"`
	Usage            bool     `json:"usage"`
	StateModes       []string `json:"state_modes"`
}

type Limits struct {
	MaximumInputTokens       uint64 `json:"maximum_input_tokens"`
	MaximumOutputTokens      uint64 `json:"maximum_output_tokens"`
	MaximumMessages          uint32 `json:"maximum_messages"`
	MaximumTools             uint16 `json:"maximum_tools"`
	MaximumParallelToolCalls uint16 `json:"maximum_parallel_tool_calls"`
	MaximumStreamSeconds     uint32 `json:"maximum_stream_seconds"`
}

type CapabilitySnapshot struct {
	SchemaVersion   string           `json:"schema_version"`
	ContractVersion string           `json:"contract_version"`
	SnapshotID      string           `json:"snapshot_id"`
	ObservedAt      string           `json:"observed_at"`
	ValidUntil      string           `json:"valid_until"`
	Provider        ProviderIdentity `json:"provider"`
	Features        Features         `json:"features"`
	Limits          Limits           `json:"limits"`
}

type ReleaseMatrix struct {
	Profile        string `json:"profile"`
	OS             string `json:"os"`
	Architecture   string `json:"architecture"`
	DeploymentMode string `json:"deployment_mode"`
	NetworkMode    string `json:"network_mode"`
}

type QualificationCase struct {
	Kind                 string `json:"kind"`
	FixtureDigest        string `json:"fixture_digest"`
	Outcome              string `json:"outcome"`
	TraceDigest          string `json:"trace_digest"`
	DurationMilliseconds uint64 `json:"duration_milliseconds"`
}

type QualificationRecord struct {
	SchemaVersion           string              `json:"schema_version"`
	ContractVersion         string              `json:"contract_version"`
	QualificationID         string              `json:"qualification_id"`
	IssuedAt                string              `json:"issued_at"`
	ExpiresAt               string              `json:"expires_at"`
	Provider                ProviderIdentity    `json:"provider"`
	CapabilityDigest        string              `json:"capability_digest"`
	ReleaseMatrix           ReleaseMatrix       `json:"release_matrix"`
	Cases                   []QualificationCase `json:"cases"`
	AggregateOutcome        string              `json:"aggregate_outcome"`
	SuiteDigest             string              `json:"suite_digest"`
	QualifierIdentityDigest string              `json:"qualifier_identity_digest"`
}
