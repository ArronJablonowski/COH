package splunk

const (
	LifecyclePolicyVersion        = "coh.splunk-lifecycle-policy/v1"
	SIDOwnershipVersion           = "coh.splunk-sid-ownership/v1"
	JobStatusVersion              = "coh.splunk-job-status/v1"
	ResultEnvelopeVersion         = "coh.splunk-result-envelope/v1"
	CancellationProofVersion      = "coh.splunk-cancellation-proof/v1"
	LifecycleDenialCorpusVersion  = "coh.splunk-lifecycle-denials/v1"
	LifecycleRedactedErrorVersion = "coh.splunk-lifecycle-redacted-error/v1"
)

type LifecyclePolicy struct {
	SchemaVersion             string   `json:"schema_version"`
	ContractVersion           string   `json:"contract_version"`
	ExecutionMode             string   `json:"execution_mode"`
	AllowPreviews             bool     `json:"allow_previews"`
	StatusBuckets             uint32   `json:"status_buckets"`
	MaximumPageRows           uint32   `json:"maximum_page_rows"`
	MinimumPollIntervalMillis uint64   `json:"minimum_poll_interval_millis"`
	CancellationWaitMillis    uint64   `json:"cancellation_wait_millis"`
	Operations                []string `json:"operations"`
	AllowedStates             []string `json:"allowed_states"`
}

type SIDOwnership struct {
	SchemaVersion      string `json:"schema_version"`
	ContractVersion    string `json:"contract_version"`
	SourceID           string `json:"source_id"`
	QueryDigest        string `json:"query_digest"`
	PlanDigest         string `json:"plan_digest"`
	SIDDigest          string `json:"sid_digest"`
	OpaqueHandleDigest string `json:"opaque_handle_digest"`
	ExpiresAt          string `json:"expires_at"`
	SIDExposed         bool   `json:"sid_exposed"`
}

type JobStatus struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	State           string `json:"state"`
	DoneProgress    string `json:"done_progress"`
	ScanCount       uint64 `json:"scan_count"`
	EventCount      uint64 `json:"event_count"`
	ResultCount     uint64 `json:"result_count"`
	DurationMillis  uint64 `json:"duration_millis"`
	Done            bool   `json:"done"`
	Failed          bool   `json:"failed"`
	Finalized       bool   `json:"finalized"`
	RealTime        bool   `json:"real_time"`
	Zombie          bool   `json:"zombie"`
}

type ResultEnvelope struct {
	SchemaVersion   string              `json:"schema_version"`
	ContractVersion string              `json:"contract_version"`
	Offset          uint64              `json:"offset"`
	Count           uint32              `json:"count"`
	Total           uint64              `json:"total"`
	Fields          []string            `json:"fields"`
	Results         []map[string]string `json:"results"`
	Messages        []string            `json:"messages"`
	Truncated       bool                `json:"truncated"`
	ResultDigest    string              `json:"result_digest"`
}

type CancellationProof struct {
	SchemaVersion   string  `json:"schema_version"`
	ContractVersion string  `json:"contract_version"`
	Outcome         string  `json:"outcome"`
	ReasonCode      string  `json:"reason_code"`
	RequestedAt     string  `json:"requested_at"`
	ConfirmedAt     *string `json:"confirmed_at"`
	RequestDigest   string  `json:"request_digest"`
	ResponseDigest  string  `json:"response_digest"`
	SIDExposed      bool    `json:"sid_exposed"`
}
