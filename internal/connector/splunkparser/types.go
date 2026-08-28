// Package splunkparser compiles COH's restricted SPL profile into bounded,
// authority-bound native Splunk plans.
package splunkparser

const (
	ContractVersion       = "1.0.0"
	ValidatorVersion      = "splunk-parser-1.0.0"
	DefinitionVersion     = "coh.splunk-parser-definition/v1"
	PlanVersion           = "coh.splunk-plan/v1"
	DecisionVersion       = "coh.splunk-parser-decision/v1"
	RegistryVersion       = "coh.splunk-command-registry/v1"
	DenialCorpusVersion   = "coh.splunk-parser-denials/v1"
	RedactedAuditVersion  = "coh.splunk-parser-audit/v1"
	RevocationVersion     = "coh.splunk-parser-revocation/v1"
	MaximumDocumentBytes  = 1 << 20
	MaximumInputBytes     = 65536
	MaximumTokens         = 4096
	MaximumCommands       = 8
	MaximumSubsearchDepth = 2
	MaximumSubsearches    = 4
	MaximumPredicateDepth = 16
	MaximumPredicateNodes = 256
	MaximumProjection     = 256
	MaximumAggregations   = 16
	MaximumGroupFields    = 16
	MaximumSortFields     = 8
	MaximumSubsearchRows  = 100
)

type Definition struct {
	SchemaVersion     string         `json:"schema_version"`
	ContractVersion   string         `json:"contract_version"`
	ValidatorVersion  string         `json:"validator_version"`
	SourceID          string         `json:"source_id"`
	Resources         []ResourceRule `json:"resources"`
	Fields            []FieldRule    `json:"fields"`
	DefaultProjection []string       `json:"default_projection"`
	StableSort        []SortRule     `json:"stable_sort"`
	TimestampField    string         `json:"timestamp_field"`
	TenantField       string         `json:"tenant_field"`
	SourceField       string         `json:"source_field"`
	HardMaximumRows   uint64         `json:"hard_maximum_rows"`
}

type ResourceRule struct {
	ID          string `json:"id"`
	VendorIndex string `json:"vendor_index"`
}

type FieldRule struct {
	Name         string `json:"name"`
	VendorName   string `json:"vendor_name"`
	Type         string `json:"type"`
	Projectable  bool   `json:"projectable"`
	Filterable   bool   `json:"filterable"`
	Sortable     bool   `json:"sortable"`
	Aggregatable bool   `json:"aggregatable"`
}

type SortRule struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
}

type Plan struct {
	SchemaVersion         string           `json:"schema_version"`
	ContractVersion       string           `json:"contract_version"`
	ValidatorVersion      string           `json:"validator_version"`
	QueryID               string           `json:"query_id"`
	SourceID              string           `json:"source_id"`
	ResourceIDs           []string         `json:"resource_ids"`
	CanonicalSPL          string           `json:"canonical_spl"`
	Columns               []Column         `json:"columns"`
	Aggregations          []Aggregation    `json:"aggregations"`
	Sort                  []SortRule       `json:"sort"`
	Earliest              string           `json:"earliest"`
	Latest                string           `json:"latest"`
	MaximumRows           uint64           `json:"maximum_rows"`
	MaximumBytes          uint64           `json:"maximum_bytes"`
	MaximumDurationMillis uint64           `json:"maximum_duration_millis"`
	SubsearchCount        uint32           `json:"subsearch_count"`
	CommandCount          uint32           `json:"command_count"`
	QueryDigest           string           `json:"query_digest"`
	ScopeDigest           string           `json:"scope_digest"`
	CapabilityDigest      string           `json:"capability_digest"`
	SchemaDigest          string           `json:"schema_digest"`
	Authority             AuthorityBinding `json:"authority"`
	RegistryDigest        string           `json:"registry_digest"`
	ParserReceiptDigest   string           `json:"parser_receipt_digest"`
	MandatoryFilterDigest string           `json:"mandatory_filter_digest"`
	PlanDigest            string           `json:"plan_digest"`
}

type AuthorityBinding struct {
	ActorID                string `json:"actor_id"`
	AuthorizationDigest    string `json:"authorization_digest"`
	PolicyDecisionDigest   string `json:"policy_decision_digest"`
	AuditReservationDigest string `json:"audit_reservation_digest"`
}

type Column struct {
	LogicalName string `json:"logical_name"`
	VendorName  string `json:"vendor_name"`
	Type        string `json:"type"`
	Nullable    bool   `json:"nullable"`
}

type Aggregation struct {
	Function     string `json:"function"`
	InputLogical string `json:"input_logical"`
	InputVendor  string `json:"input_vendor"`
	OutputName   string `json:"output_name"`
	OutputType   string `json:"output_type"`
}

type PolicyDecision struct {
	SchemaVersion          string   `json:"schema_version"`
	ContractVersion        string   `json:"contract_version"`
	DecisionID             string   `json:"decision_id"`
	QueryID                string   `json:"query_id"`
	Outcome                string   `json:"outcome"`
	ReasonCodes            []string `json:"reason_codes"`
	ValidatorVersion       string   `json:"validator_version"`
	ActorID                string   `json:"actor_id"`
	ScopeDigest            string   `json:"scope_digest"`
	QueryDigest            string   `json:"query_digest"`
	CapabilityDigest       string   `json:"capability_digest"`
	SchemaDigest           string   `json:"schema_digest"`
	PlanDigest             string   `json:"plan_digest"`
	RegistryDigest         string   `json:"registry_digest"`
	ParserReceiptDigest    string   `json:"parser_receipt_digest"`
	PolicyDecisionDigest   string   `json:"policy_decision_digest"`
	AuditReservationDigest string   `json:"audit_reservation_digest"`
	ObservedAt             string   `json:"observed_at"`
	ValidUntil             string   `json:"valid_until"`
	Digest                 string   `json:"digest"`
}

type CommandRegistry struct {
	SchemaVersion      string        `json:"schema_version"`
	ContractVersion    string        `json:"contract_version"`
	RegistryVersion    string        `json:"registry_version"`
	AllowedCommands    []string      `json:"allowed_commands"`
	ProhibitedCommands []CommandRule `json:"prohibited_commands"`
	BackticksAllowed   bool          `json:"backticks_allowed"`
	MacrosAllowed      bool          `json:"macros_allowed"`
	LookupsAllowed     bool          `json:"lookups_allowed"`
	CustomAllowed      bool          `json:"custom_allowed"`
	Digest             string        `json:"digest"`
}

type CommandRule struct {
	Name  string `json:"name"`
	Class string `json:"class"`
}

type DenialCorpus struct {
	SchemaVersion   string       `json:"schema_version"`
	ContractVersion string       `json:"contract_version"`
	Cases           []DenialCase `json:"cases"`
}

type DenialCase struct {
	Class     string `json:"class"`
	Input     string `json:"input"`
	Reason    string `json:"reason"`
	CoveredBy string `json:"covered_by"`
}

type RedactedAudit struct {
	SchemaVersion          string   `json:"schema_version"`
	ContractVersion        string   `json:"contract_version"`
	Event                  string   `json:"event"`
	Outcome                string   `json:"outcome"`
	ReasonCodes            []string `json:"reason_codes"`
	QueryID                string   `json:"query_id"`
	ActorID                string   `json:"actor_id"`
	ScopeDigest            string   `json:"scope_digest"`
	QueryDigest            string   `json:"query_digest"`
	PlanDigest             string   `json:"plan_digest"`
	RegistryDigest         string   `json:"registry_digest"`
	ParserReceiptDigest    string   `json:"parser_receipt_digest"`
	PolicyDecisionDigest   string   `json:"policy_decision_digest"`
	AuditReservationDigest string   `json:"audit_reservation_digest"`
	NativeTextExposed      bool     `json:"native_text_exposed"`
	LiteralExposed         bool     `json:"literal_exposed"`
	CredentialExposed      bool     `json:"credential_exposed"`
	VendorBodyExposed      bool     `json:"vendor_body_exposed"`
	SIDExposed             bool     `json:"sid_exposed"`
}

type RevocationEvidence struct {
	SchemaVersion          string `json:"schema_version"`
	ContractVersion        string `json:"contract_version"`
	DecisionDigest         string `json:"decision_digest"`
	RevocationDigest       string `json:"revocation_digest"`
	AuditReservationDigest string `json:"audit_reservation_digest"`
	ReasonCode             string `json:"reason_code"`
	ObservedAt             string `json:"observed_at"`
	ExecutionPermitted     bool   `json:"execution_permitted"`
}
