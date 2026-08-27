package queryconnector

const (
	ContractVersion = "1.0.0"

	CapabilitySchemaVersion = "coh.query-capability/v1"
	QuerySchemaVersion      = "coh.query-request/v1"
	SchemaSchemaVersion     = "coh.query-schema/v1"
	ValidationSchemaVersion = "coh.query-validation/v1"
	ExecutionSchemaVersion  = "coh.query-execution/v1"
	PollSchemaVersion       = "coh.query-poll/v1"
	PageSchemaVersion       = "coh.query-page/v1"
	CancellationVersion     = "coh.query-cancellation/v1"

	MaximumDocumentBytes = 1 << 20
)

type Scope struct {
	OrganizationID string   `json:"organization_id"`
	TenantID       string   `json:"tenant_id"`
	CaseID         string   `json:"case_id"`
	SourceID       string   `json:"source_id"`
	ResourceIDs    []string `json:"resource_ids"`
}

type AuthorityBinding struct {
	ActorID                string `json:"actor_id"`
	AuthorizationDigest    string `json:"authorization_digest"`
	PolicyDecisionDigest   string `json:"policy_decision_digest"`
	AuditReservationDigest string `json:"audit_reservation_digest"`
}

type TimeRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type Limits struct {
	MaximumRows           uint64 `json:"maximum_rows"`
	MaximumBytes          uint64 `json:"maximum_bytes"`
	MaximumDurationMillis uint64 `json:"maximum_duration_millis"`
	MaximumPages          uint32 `json:"maximum_pages"`
	MaximumSlices         uint32 `json:"maximum_slices"`
	MaximumCostMillionths uint64 `json:"maximum_cost_millionths"`
	RequestsPerMinute     uint32 `json:"requests_per_minute"`
}

type CapabilitySnapshot struct {
	SchemaVersion        string   `json:"schema_version"`
	ContractVersion      string   `json:"contract_version"`
	SnapshotID           string   `json:"snapshot_id"`
	SourceID             string   `json:"source_id"`
	AdapterVersion       string   `json:"adapter_version"`
	ObservedAt           string   `json:"observed_at"`
	ValidUntil           string   `json:"valid_until"`
	QueryLanguages       []string `json:"query_languages"`
	Features             Features `json:"features"`
	HardLimits           Limits   `json:"hard_limits"`
	SourceIdentityDigest string   `json:"source_identity_digest"`
}

type Features struct {
	ReadOnly        bool `json:"read_only"`
	SchemaDiscovery bool `json:"schema_discovery"`
	Validation      bool `json:"validation"`
	Polling         bool `json:"polling"`
	Paging          bool `json:"paging"`
	Cancellation    bool `json:"cancellation"`
	Statistics      bool `json:"statistics"`
}

type SchemaRequest struct {
	RequestID        string           `json:"request_id"`
	Scope            Scope            `json:"scope"`
	Authority        AuthorityBinding `json:"authority"`
	CapabilityDigest string           `json:"capability_digest"`
	Cursor           *HandleRef       `json:"cursor"`
	Limits           Limits           `json:"limits"`
}

type SchemaPage struct {
	SchemaVersion    string        `json:"schema_version"`
	ContractVersion  string        `json:"contract_version"`
	RequestID        string        `json:"request_id"`
	SchemaDigest     string        `json:"schema_digest"`
	Entries          []SchemaEntry `json:"entries"`
	NextCursor       *HandleRef    `json:"next_cursor"`
	Complete         bool          `json:"complete"`
	ProvenanceDigest string        `json:"provenance_digest"`
}

type SchemaEntry struct {
	ResourceID string `json:"resource_id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable"`
}

type Query struct {
	SchemaVersion    string           `json:"schema_version"`
	ContractVersion  string           `json:"contract_version"`
	QueryID          string           `json:"query_id"`
	Scope            Scope            `json:"scope"`
	Authority        AuthorityBinding `json:"authority"`
	CapabilityDigest string           `json:"capability_digest"`
	SchemaDigest     string           `json:"schema_digest"`
	Language         string           `json:"language"`
	NativeText       string           `json:"native_text"`
	TimeRange        TimeRange        `json:"time_range"`
	Limits           Limits           `json:"limits"`
	RequestedAt      string           `json:"requested_at"`
	Deadline         string           `json:"deadline"`
}

type ValidationResult struct {
	SchemaVersion        string   `json:"schema_version"`
	ContractVersion      string   `json:"contract_version"`
	QueryID              string   `json:"query_id"`
	Outcome              string   `json:"outcome"`
	ReasonCodes          []string `json:"reason_codes"`
	ValidatorVersion     string   `json:"validator_version"`
	CanonicalQueryDigest string   `json:"canonical_query_digest"`
	ProvenanceDigest     string   `json:"provenance_digest"`
}

// HandleRef identifies adapter-held state without exposing a vendor token,
// credential, URL, or generic transport payload to the control plane.
type HandleRef struct {
	HandleID     string `json:"handle_id"`
	Kind         string `json:"kind"`
	SourceID     string `json:"source_id"`
	OpaqueDigest string `json:"opaque_digest"`
	IssuedAt     string `json:"issued_at"`
	ExpiresAt    string `json:"expires_at"`
}

type Execution struct {
	SchemaVersion    string    `json:"schema_version"`
	ContractVersion  string    `json:"contract_version"`
	QueryID          string    `json:"query_id"`
	AttemptID        string    `json:"attempt_id"`
	Handle           HandleRef `json:"handle"`
	Outcome          string    `json:"outcome"`
	StartedAt        string    `json:"started_at"`
	ProvenanceDigest string    `json:"provenance_digest"`
}

type PollRequest struct {
	QueryID   string           `json:"query_id"`
	AttemptID string           `json:"attempt_id"`
	Handle    HandleRef        `json:"handle"`
	Authority AuthorityBinding `json:"authority"`
}

type PollResult struct {
	SchemaVersion    string       `json:"schema_version"`
	ContractVersion  string       `json:"contract_version"`
	QueryID          string       `json:"query_id"`
	AttemptID        string       `json:"attempt_id"`
	Outcome          string       `json:"outcome"`
	Page             *ResultPage  `json:"page"`
	Statistics       Statistics   `json:"statistics"`
	Completeness     Completeness `json:"completeness"`
	ProvenanceDigest string       `json:"provenance_digest"`
}

type ResultPage struct {
	SchemaVersion    string           `json:"schema_version"`
	ContractVersion  string           `json:"contract_version"`
	QueryID          string           `json:"query_id"`
	AttemptID        string           `json:"attempt_id"`
	PageNumber       uint32           `json:"page_number"`
	Rows             []map[string]any `json:"rows"`
	NextPage         *HandleRef       `json:"next_page"`
	ResultDigest     string           `json:"result_digest"`
	Completeness     Completeness     `json:"completeness"`
	Statistics       Statistics       `json:"statistics"`
	ProvenanceDigest string           `json:"provenance_digest"`
}

type Completeness struct {
	Status          string   `json:"status"`
	ReasonCodes     []string `json:"reason_codes"`
	Truncated       bool     `json:"truncated"`
	Partial         bool     `json:"partial"`
	VendorConfirmed bool     `json:"vendor_confirmed"`
}

type Statistics struct {
	RowsScanned     uint64 `json:"rows_scanned"`
	RowsReturned    uint64 `json:"rows_returned"`
	BytesReturned   uint64 `json:"bytes_returned"`
	DurationMillis  uint64 `json:"duration_millis"`
	PagesReturned   uint32 `json:"pages_returned"`
	SlicesCompleted uint32 `json:"slices_completed"`
	CostMillionths  uint64 `json:"cost_millionths"`
}

type PageRequest struct {
	QueryID   string           `json:"query_id"`
	AttemptID string           `json:"attempt_id"`
	Handle    HandleRef        `json:"handle"`
	Authority AuthorityBinding `json:"authority"`
	Limits    Limits           `json:"limits"`
}

type CancelRequest struct {
	QueryID     string           `json:"query_id"`
	AttemptID   string           `json:"attempt_id"`
	Handle      HandleRef        `json:"handle"`
	Authority   AuthorityBinding `json:"authority"`
	RequestedAt string           `json:"requested_at"`
}

type Cancellation struct {
	SchemaVersion    string  `json:"schema_version"`
	ContractVersion  string  `json:"contract_version"`
	QueryID          string  `json:"query_id"`
	AttemptID        string  `json:"attempt_id"`
	Outcome          string  `json:"outcome"`
	RequestedAt      string  `json:"requested_at"`
	ConfirmedAt      *string `json:"confirmed_at"`
	ProvenanceDigest string  `json:"provenance_digest"`
}
