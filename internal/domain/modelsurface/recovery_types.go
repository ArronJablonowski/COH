package modelsurface

type CoveredSource struct {
	Ordinal                     uint64   `json:"ordinal"`
	SourceRecordID              string   `json:"source_record_id"`
	SourceDigest                string   `json:"source_digest"`
	EvidenceIDs                 []string `json:"evidence_ids"`
	NormalizedTime              string   `json:"normalized_time"`
	OriginalTimezone            string   `json:"original_timezone"`
	Precision                   string   `json:"precision"`
	ClockUncertaintyNanoseconds uint64   `json:"clock_uncertainty_nanoseconds"`
	OrderConfidence             string   `json:"order_confidence"`
	ResultState                 string   `json:"result_state"`
	Completeness                string   `json:"completeness"`
	Uncertainty                 string   `json:"uncertainty"`
}

type Artifact struct {
	ArtifactID     string `json:"artifact_id"`
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Length         uint64 `json:"length"`
	Classification string `json:"classification"`
	Immutable      bool   `json:"immutable"`
}

type CompactionReplacement struct {
	SchemaVersion             string          `json:"schema_version"`
	ContractVersion           string          `json:"contract_version"`
	ReplacementID             string          `json:"replacement_id"`
	Scope                     Scope           `json:"scope"`
	RunID                     string          `json:"run_id"`
	CompactionID              string          `json:"compaction_id"`
	ReplacementSourceRecordID string          `json:"replacement_source_record_id"`
	CoveredSources            []CoveredSource `json:"covered_sources"`
	SummaryArtifact           Artifact        `json:"summary_artifact"`
	CoverageDigest            string          `json:"coverage_digest,omitempty"`
	ReplacementDigest         string          `json:"replacement_digest,omitempty"`
	CreatedAt                 string          `json:"created_at"`
}

type Transition struct {
	SchemaVersion            string `json:"schema_version"`
	ContractVersion          string `json:"contract_version"`
	TransitionID             string `json:"transition_id"`
	RequestID                string `json:"request_id"`
	AttemptID                string `json:"attempt_id"`
	Scope                    Scope  `json:"scope"`
	RunID                    string `json:"run_id"`
	Phase                    string `json:"phase"`
	Revision                 uint64 `json:"revision"`
	ProjectionDigest         string `json:"projection_digest"`
	BindingDigest            string `json:"binding_digest"`
	ProviderRoute            string `json:"provider_route"`
	ProviderAttempt          uint64 `json:"provider_attempt"`
	StreamCursor             uint64 `json:"stream_cursor"`
	TerminalOutcome          string `json:"terminal_outcome"`
	PreviousTransitionDigest string `json:"previous_transition_digest"`
	TransitionDigest         string `json:"transition_digest,omitempty"`
	CreatedAt                string `json:"created_at"`
	UpdatedAt                string `json:"updated_at"`
}
