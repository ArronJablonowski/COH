// Package temporaltime normalizes source time without inventing precision or
// ordering certainty and binds every result to immutable case evidence.
package temporaltime

import "time"

const (
	CommandSchemaVersion    = "coh.time-normalization-command/v1"
	RecordSchemaVersion     = "coh.time-normalization-record/v1"
	ComparisonSchemaVersion = "coh.time-comparison/v1"
	ReceiptSchemaVersion    = "coh.time-normalization-receipt/v1"
	ContractVersion         = "1.0.0"
	MaximumInputBytes       = 1 << 20
)

type Precision string

const (
	Nanosecond       Precision = "nanosecond"
	Microsecond      Precision = "microsecond"
	Millisecond      Precision = "millisecond"
	Second           Precision = "second"
	Minute           Precision = "minute"
	Hour             Precision = "hour"
	Day              Precision = "day"
	UnknownPrecision Precision = "unknown"
)

type EvidenceState string

const (
	Observed    EvidenceState = "observed"
	Negative    EvidenceState = "negative"
	Gap         EvidenceState = "gap"
	Partial     EvidenceState = "partial"
	Conflicting EvidenceState = "conflicting"
)

type Completeness string

const (
	Complete                Completeness = "complete"
	PartialCompleteness     Completeness = "partial"
	Truncated               Completeness = "truncated"
	UnavailableCompleteness Completeness = "unavailable"
	UnknownCompleteness     Completeness = "unknown"
)

type Outcome string

const (
	Normalized            Outcome = "normalized"
	Unresolved            Outcome = "unresolved"
	Denied                Outcome = "denied"
	CanceledOutcome       Outcome = "canceled"
	TimeoutOutcome        Outcome = "timeout"
	DependencyUnavailable Outcome = "dependency_unavailable"
)

type Reason string

const (
	ReasonNormalized            Reason = "normalized"
	TimezoneUnresolved          Reason = "timezone_unresolved"
	TimezoneMismatch            Reason = "timezone_mismatch"
	DSTGap                      Reason = "dst_gap"
	PrecisionUnknown            Reason = "precision_unknown"
	CalibrationUnresolved       Reason = "calibration_unresolved"
	InvalidSourceText           Reason = "invalid_source_text"
	ParserNotRegistered         Reason = "parser_not_registered"
	FormatNotSupported          Reason = "format_not_supported"
	EvidenceBindingMismatch     Reason = "evidence_binding_mismatch"
	EvidenceStateInvalid        Reason = "evidence_state_invalid"
	ArithmeticOverflow          Reason = "arithmetic_overflow"
	IntervalInvalid             Reason = "interval_invalid"
	IdempotencyConflict         Reason = "idempotency_conflict"
	ContextCanceled             Reason = "context_canceled"
	ContextDeadline             Reason = "context_deadline"
	DependencyUnavailableReason Reason = "dependency_unavailable"
)

type Case struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type SourceBinding struct {
	EnvelopeID             string `json:"envelope_id"`
	EnvelopeDigest         string `json:"envelope_digest"`
	ArtifactDigest         string `json:"artifact_digest"`
	ManifestDigest         string `json:"manifest_digest"`
	IngestReceiptDigest    string `json:"ingest_receipt_digest"`
	SourceProvenanceDigest string `json:"source_provenance_digest"`
	SourceIdentityDigest   string `json:"source_identity_digest"`
	FieldSelector          string `json:"field_selector"`
	DeduplicationDigest    string `json:"deduplication_digest"`
}

type OriginalTime struct {
	Text      string    `json:"text"`
	Format    string    `json:"format"`
	Precision Precision `json:"precision"`
}

type ParserIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type TimezoneKind string

const (
	ExplicitOffset  TimezoneKind = "explicit_offset"
	IANA            TimezoneKind = "iana"
	MissingTimezone TimezoneKind = "missing"
)

type TimezoneAssertion struct {
	Kind          TimezoneKind `json:"kind"`
	Name          string       `json:"name"`
	OffsetMinutes *int16       `json:"offset_minutes"`
	TZDataVersion string       `json:"tzdata_version"`
	TZDataDigest  string       `json:"tzdata_digest"`
}

type CalibrationState string

const (
	KnownCalibration   CalibrationState = "known"
	UnknownCalibration CalibrationState = "unknown"
)

type ClockKind string

const (
	SourceClock    ClockKind = "source"
	CollectorClock ClockKind = "collector"
	ServerClock    ClockKind = "server"
	DeviceClock    ClockKind = "device"
	UnknownClock   ClockKind = "unknown"
)

type Calibration struct {
	State               CalibrationState `json:"state"`
	ClockKind           ClockKind        `json:"clock_kind"`
	Identity            string           `json:"identity"`
	IdentityDigest      string           `json:"identity_digest"`
	EstimateNanoseconds *int64           `json:"estimate_nanoseconds"`
	RadiusNanoseconds   *int64           `json:"radius_nanoseconds"`
}

type Command struct {
	SchemaVersion   string            `json:"schema_version"`
	ContractVersion string            `json:"contract_version"`
	OperationID     string            `json:"operation_id"`
	IdempotencyKey  string            `json:"idempotency_key"`
	Case            Case              `json:"case"`
	SourceBinding   SourceBinding     `json:"source_binding"`
	OriginalTime    OriginalTime      `json:"original_time"`
	Parser          ParserIdentity    `json:"parser"`
	Timezone        TimezoneAssertion `json:"timezone"`
	Calibration     Calibration       `json:"calibration"`
	EvidenceState   EvidenceState     `json:"evidence_state"`
	Completeness    Completeness      `json:"completeness"`
	RequestedAt     string            `json:"requested_at"`
	Deadline        string            `json:"deadline"`
}

// CivilTime is a parser result. It deliberately has no location and therefore
// cannot silently convert itself to UTC.
type CivilTime struct {
	Year       int
	Month      time.Month
	Day        int
	Hour       int
	Minute     int
	Second     int
	Nanosecond int
	Precision  Precision
	// SourceOffsetMinutes is present only when the source text itself carried
	// an offset. Metadata-supplied timezone assertions remain separate.
	SourceOffsetMinutes *int16
}

type ParserKind string

const (
	BuiltinStrictParser ParserKind = "builtin_strict"
)

type ParserSpec struct {
	Identity ParserIdentity
	Kind     ParserKind
}

type ResolvedInterval struct {
	EarliestUTC   time.Time
	LatestUTC     time.Time
	OffsetMinutes int16
}

type DSTState string

const (
	DSTExact         DSTState = "exact"
	DSTFold          DSTState = "fold"
	DSTGapState      DSTState = "gap"
	DSTNotApplicable DSTState = "not_applicable"
	DSTUnresolved    DSTState = "unresolved"
)

type TimezoneResolution struct {
	DSTState  DSTState
	Intervals []ResolvedInterval
}

type TimezoneResult struct {
	Assertion              TimezoneAssertion `json:"assertion"`
	DSTState               DSTState          `json:"dst_state"`
	ResolvedOffsetsMinutes []int16           `json:"resolved_offsets_minutes"`
}

type IntervalKind string

const (
	Bounded   IntervalKind = "bounded"
	Unbounded IntervalKind = "unbounded"
)

type Interval struct {
	Kind        IntervalKind `json:"kind"`
	EarliestUTC *string      `json:"earliest_utc"`
	LatestUTC   *string      `json:"latest_utc"`
}

type Record struct {
	SchemaVersion   string         `json:"schema_version"`
	ContractVersion string         `json:"contract_version"`
	RecordID        string         `json:"record_id"`
	OperationID     string         `json:"operation_id"`
	CommandDigest   string         `json:"command_digest"`
	Case            Case           `json:"case"`
	SourceBinding   SourceBinding  `json:"source_binding"`
	OriginalTime    OriginalTime   `json:"original_time"`
	Parser          ParserIdentity `json:"parser"`
	TimezoneResult  TimezoneResult `json:"timezone_result"`
	Calibration     Calibration    `json:"calibration"`
	CandidateUTC    []string       `json:"candidate_utc"`
	NormalizedUTC   *string        `json:"normalized_utc"`
	Interval        Interval       `json:"interval"`
	EvidenceState   EvidenceState  `json:"evidence_state"`
	Completeness    Completeness   `json:"completeness"`
	Outcome         Outcome        `json:"outcome"`
	ReasonCode      Reason         `json:"reason_code"`
	CreatedAt       string         `json:"created_at"`
}

type RecordRef struct {
	RecordID            string `json:"record_id"`
	RecordDigest        string `json:"record_digest"`
	DeduplicationDigest string `json:"deduplication_digest"`
}

type ComparisonOutcome string

const (
	Before            ComparisonOutcome = "before"
	After             ComparisonOutcome = "after"
	Equal             ComparisonOutcome = "equal"
	Overlap           ComparisonOutcome = "overlap"
	Duplicate         ComparisonOutcome = "duplicate"
	Conflict          ComparisonOutcome = "conflicting"
	UnknownComparison ComparisonOutcome = "unknown"
)

type Confidence string

const (
	Exact             Confidence = "exact"
	BoundedConfidence Confidence = "bounded"
	Ambiguous         Confidence = "ambiguous"
	UnknownConfidence Confidence = "unknown"
)

type Rationale string

const (
	DisjointIntervals            Rationale = "disjoint_intervals"
	EqualSingleton               Rationale = "equal_singleton"
	IntersectingIntervals        Rationale = "intersecting_intervals"
	SameBindingSameRecord        Rationale = "same_binding_same_record"
	SameBindingIncompatibleFacts Rationale = "same_binding_incompatible_facts"
	UnboundedInterval            Rationale = "unbounded_interval"
	UnresolvedInput              Rationale = "unresolved_input"
)

type Comparison struct {
	SchemaVersion   string            `json:"schema_version"`
	ContractVersion string            `json:"contract_version"`
	ComparisonID    string            `json:"comparison_id"`
	Case            Case              `json:"case"`
	Left            RecordRef         `json:"left"`
	Right           RecordRef         `json:"right"`
	Outcome         ComparisonOutcome `json:"outcome"`
	Confidence      Confidence        `json:"confidence"`
	Rationale       Rationale         `json:"rationale"`
	GapNanoseconds  *int64            `json:"gap_nanoseconds"`
	CreatedAt       string            `json:"created_at"`
}

type Receipt struct {
	SchemaVersion            string     `json:"schema_version"`
	ContractVersion          string     `json:"contract_version"`
	OperationID              string     `json:"operation_id"`
	IdempotencyKey           string     `json:"idempotency_key"`
	CommandDigest            string     `json:"command_digest"`
	Record                   *RecordRef `json:"record"`
	Outcome                  Outcome    `json:"outcome"`
	ReasonCode               Reason     `json:"reason_code"`
	AuditDigest              string     `json:"audit_digest"`
	PreviousProvenanceDigest *string    `json:"previous_provenance_digest"`
	ProvenanceDigest         string     `json:"provenance_digest"`
	CreatedAt                string     `json:"created_at"`
	UpdatedAt                string     `json:"updated_at"`
}

type AuditRecord struct {
	OperationID   string
	CommandDigest string
	Outcome       Outcome
	ReasonCode    Reason
	Digest        string
}

type ProvenanceRecord struct {
	OperationID    string
	CommandDigest  string
	RecordDigest   string
	PreviousDigest string
	Digest         string
}

type Commit struct {
	Command    Command
	Record     Record
	Receipt    Receipt
	Audit      AuditRecord
	Provenance ProvenanceRecord
}

type ComparisonCommit struct {
	Comparison               Comparison
	ComparisonDigest         string
	AuditDigest              string
	PreviousProvenanceDigest string
	ProvenanceDigest         string
}
