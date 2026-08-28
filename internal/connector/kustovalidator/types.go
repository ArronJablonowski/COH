// Package kustovalidator defines COH's credentialless Kusto.Language helper
// protocol and the authority-bearing Go validation boundary.
package kustovalidator

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	ContractVersion        = "1.0.0"
	ValidatorVersion       = "kusto-language-12.4.1-coh-1.0.0"
	HelperRequestVersion   = "coh.kusto-helper-request/v1"
	HelperResponseVersion  = "coh.kusto-helper-response/v1"
	RegistryVersion        = "coh.kusto-semantic-registry/v1"
	AttestationVersion     = "coh.kusto-helper-attestation/v1"
	PolicyDecisionVersion  = "coh.kusto-validator-decision/v1"
	AuditProofVersion      = "coh.kusto-validator-audit/v1"
	RevocationVersion      = "coh.kusto-validator-revocation/v1"
	DenialCorpusVersion    = "coh.kusto-validator-denials/v1"
	MaximumDocumentBytes   = 1 << 20
	MaximumQueryBytes      = 65536
	MaximumCanonicalBytes  = 131072
	MaximumTables          = 64
	MaximumColumns         = 8192
	MaximumReasons         = 32
	MaximumDiagnostics     = 32
	MaximumRegistryEntries = 256
	MaximumRows            = 10000
)

// ValidateRequest is the authority-bearing Go boundary. Only ToHelperRequest's
// credentialless projection may cross into the helper process.
type ValidateRequest struct {
	Query                   queryconnector.Query
	Capability              queryconnector.CapabilitySnapshot
	Schema                  SchemaBinding
	WorkspaceIdentityDigest string
	QualificationDigest     string
	Registry                SemanticRegistry
	Policy                  Policy
	Helper                  HelperAttestation
	IdempotencyKey          string
}

// AdmissionCheck is the complete non-secret binding presented to current
// authority, capability, schema, policy, E-stop, and audit-reservation gates.
// The post_helper phase prevents a result from crossing a revocation race.
type AdmissionCheck struct {
	Phase                   string
	Query                   queryconnector.Query
	Capability              queryconnector.CapabilitySnapshot
	HelperRequestDigest     string
	HelperResponseDigest    string
	SchemaDigest            string
	RegistryDigest          string
	HelperAttestationDigest string
	QualificationDigest     string
	EvaluatedAt             time.Time
}

type RevocationCheck struct {
	Phase                   string
	QueryID                 string
	ActorID                 string
	RequestDigest           string
	ResponseDigest          string
	HelperAttestationDigest string
	PolicyDecisionDigest    string
	AuditReservationDigest  string
}

// ValidationAdmission is the only object that can release canonical KQL.
// A denied or unaudited operation always returns its zero value.
type ValidationAdmission struct {
	Validation   queryconnector.ValidationResult
	CanonicalKQL string
	Decision     PolicyDecision
	Audit        AuditProof
	Replayed     bool
}

type ReplayRecord struct {
	RequestDigest string
	Admission     ValidationAdmission
}

type Policy struct {
	Profile              string `json:"profile"`
	RegistryDigest       string `json:"registry_digest"`
	MaximumRows          uint64 `json:"maximum_rows"`
	MaximumQueryBytes    uint32 `json:"maximum_query_bytes"`
	MaximumSyntaxNodes   uint32 `json:"maximum_syntax_nodes"`
	MaximumSyntaxDepth   uint32 `json:"maximum_syntax_depth"`
	MaximumOperators     uint32 `json:"maximum_operators"`
	MaximumOutputColumns uint32 `json:"maximum_output_columns"`
	MaximumAggregates    uint32 `json:"maximum_aggregates"`
	MaximumUnionOperands uint32 `json:"maximum_union_operands"`
}

type HelperRequest struct {
	SchemaVersion             string         `json:"schema_version"`
	ContractVersion           string         `json:"contract_version"`
	RequestID                 string         `json:"request_id"`
	Operation                 string         `json:"operation"`
	Query                     string         `json:"query"`
	QueryDigest               string         `json:"query_digest"`
	SourceID                  string         `json:"source_id"`
	ResourceIDs               []string       `json:"resource_ids"`
	WorkspaceIdentityDigest   string         `json:"workspace_identity_digest"`
	QualificationDigest       string         `json:"qualification_digest"`
	CapabilityDigest          string         `json:"capability_digest"`
	Schema                    SchemaBinding  `json:"schema"`
	SchemaDigest              string         `json:"schema_digest"`
	Policy                    Policy         `json:"policy"`
	HelperIdentityExpectation HelperIdentity `json:"helper_identity_expectation"`
	RequestedRows             uint64         `json:"requested_rows"`
	Deadline                  string         `json:"deadline"`
	RequestDigest             string         `json:"request_digest"`
}

type SchemaBinding struct {
	Database   string        `json:"database"`
	ObservedAt string        `json:"observed_at"`
	ValidUntil string        `json:"valid_until"`
	Tables     []SchemaTable `json:"tables"`
}

type SchemaTable struct {
	Name    string         `json:"name"`
	Columns []SchemaColumn `json:"columns"`
}

type SchemaColumn struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
}

type HelperIdentity struct {
	Name                 string `json:"name"`
	Version              string `json:"version"`
	RID                  string `json:"rid"`
	ArtifactDigest       string `json:"artifact_digest"`
	PackageClosureDigest string `json:"package_closure_digest"`
	RuntimeDigest        string `json:"runtime_digest"`
	RegistryDigest       string `json:"registry_digest"`
}

type HelperResponse struct {
	SchemaVersion      string            `json:"schema_version"`
	ContractVersion    string            `json:"contract_version"`
	RequestID          string            `json:"request_id"`
	RequestDigest      string            `json:"request_digest"`
	Outcome            string            `json:"outcome"`
	ReasonCodes        []string          `json:"reason_codes"`
	Diagnostics        []Diagnostic      `json:"diagnostics"`
	CanonicalKQL       string            `json:"canonical_kql"`
	CanonicalKQLDigest string            `json:"canonical_kql_digest"`
	OriginalTreeDigest string            `json:"original_tree_digest"`
	BoundedTreeDigest  string            `json:"bounded_tree_digest"`
	Semantic           SemanticInventory `json:"semantic"`
	OutputColumns      []OutputColumn    `json:"output_columns"`
	TerminalTake       uint64            `json:"terminal_take"`
	SchemaDigest       string            `json:"schema_digest"`
	RegistryDigest     string            `json:"registry_digest"`
	HelperIdentity     HelperIdentity    `json:"helper_identity"`
	ProvenanceDigest   string            `json:"provenance_digest"`
	ResponseDigest     string            `json:"response_digest"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Class    string `json:"class"`
}

type SemanticInventory struct {
	Tables    []string `json:"tables"`
	Columns   []string `json:"columns"`
	Operators []string `json:"operators"`
	Functions []string `json:"functions"`
}

type OutputColumn struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
}

type SemanticRegistry struct {
	SchemaVersion          string   `json:"schema_version"`
	ContractVersion        string   `json:"contract_version"`
	ValidatorVersion       string   `json:"validator_version"`
	AllowedOperators       []string `json:"allowed_operators"`
	AllowedFunctions       []string `json:"allowed_functions"`
	AllowedAggregates      []string `json:"allowed_aggregates"`
	ProhibitedConstructs   []string `json:"prohibited_constructs"`
	StoredFunctionsAllowed bool     `json:"stored_functions_allowed"`
	EvaluateAllowed        bool     `json:"evaluate_allowed"`
	ExternalDataAllowed    bool     `json:"external_data_allowed"`
	CrossClusterAllowed    bool     `json:"cross_cluster_allowed"`
	DynamicOutputAllowed   bool     `json:"dynamic_output_allowed"`
	Digest                 string   `json:"digest"`
}

type HelperAttestation struct {
	SchemaVersion        string         `json:"schema_version"`
	ContractVersion      string         `json:"contract_version"`
	AttestationID        string         `json:"attestation_id"`
	ObservedAt           string         `json:"observed_at"`
	ValidUntil           string         `json:"valid_until"`
	Identity             HelperIdentity `json:"identity"`
	KustoLanguageVersion string         `json:"kusto_language_version"`
	DotnetSDKVersion     string         `json:"dotnet_sdk_version"`
	DotnetRuntimeVersion string         `json:"dotnet_runtime_version"`
	ManifestDigest       string         `json:"manifest_digest"`
	SBOMDigest           string         `json:"sbom_digest"`
	ProvenanceDigest     string         `json:"provenance_digest"`
	NetworkDenied        bool           `json:"network_denied"`
	CredentialClasses    []string       `json:"credential_classes"`
	Reproducible         bool           `json:"reproducible"`
	Digest               string         `json:"digest"`
}

type PolicyDecision struct {
	SchemaVersion           string   `json:"schema_version"`
	ContractVersion         string   `json:"contract_version"`
	DecisionID              string   `json:"decision_id"`
	QueryID                 string   `json:"query_id"`
	Outcome                 string   `json:"outcome"`
	ReasonCodes             []string `json:"reason_codes"`
	ActorID                 string   `json:"actor_id"`
	ScopeDigest             string   `json:"scope_digest"`
	RequestDigest           string   `json:"request_digest"`
	ResponseDigest          string   `json:"response_digest"`
	CapabilityDigest        string   `json:"capability_digest"`
	SchemaDigest            string   `json:"schema_digest"`
	RegistryDigest          string   `json:"registry_digest"`
	HelperAttestationDigest string   `json:"helper_attestation_digest"`
	PolicyDecisionDigest    string   `json:"policy_decision_digest"`
	AuditReservationDigest  string   `json:"audit_reservation_digest"`
	ObservedAt              string   `json:"observed_at"`
	ValidUntil              string   `json:"valid_until"`
	Digest                  string   `json:"digest"`
}

type AuditProof struct {
	SchemaVersion           string   `json:"schema_version"`
	ContractVersion         string   `json:"contract_version"`
	Event                   string   `json:"event"`
	Outcome                 string   `json:"outcome"`
	ReasonCodes             []string `json:"reason_codes"`
	QueryID                 string   `json:"query_id"`
	ActorID                 string   `json:"actor_id"`
	ScopeDigest             string   `json:"scope_digest"`
	RequestDigest           string   `json:"request_digest"`
	ResponseDigest          string   `json:"response_digest"`
	RegistryDigest          string   `json:"registry_digest"`
	HelperAttestationDigest string   `json:"helper_attestation_digest"`
	PolicyDecisionDigest    string   `json:"policy_decision_digest"`
	AuditReservationDigest  string   `json:"audit_reservation_digest"`
	AuditRecordDigest       string   `json:"audit_record_digest"`
	QueryTextExposed        bool     `json:"query_text_exposed"`
	LiteralExposed          bool     `json:"literal_exposed"`
	SchemaNameExposed       bool     `json:"schema_name_exposed"`
	WorkspaceExposed        bool     `json:"workspace_exposed"`
	CredentialExposed       bool     `json:"credential_exposed"`
	ExecutablePathExposed   bool     `json:"executable_path_exposed"`
	StderrExposed           bool     `json:"stderr_exposed"`
}

type RevocationEvidence struct {
	SchemaVersion           string `json:"schema_version"`
	ContractVersion         string `json:"contract_version"`
	DecisionDigest          string `json:"decision_digest"`
	HelperAttestationDigest string `json:"helper_attestation_digest"`
	RevocationDigest        string `json:"revocation_digest"`
	AuditReservationDigest  string `json:"audit_reservation_digest"`
	ReasonCode              string `json:"reason_code"`
	ObservedAt              string `json:"observed_at"`
	ValidationPermitted     bool   `json:"validation_permitted"`
	ExecutionPermitted      bool   `json:"execution_permitted"`
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

// Helper executes only the closed credentialless helper protocol.
type Helper interface {
	Validate(context.Context, HelperRequest) (HelperResponse, error)
}

type AdmissionControl interface {
	CheckKustoValidation(context.Context, AdmissionCheck) error
}

type HelperTrust interface {
	VerifyKustoHelper(context.Context, HelperAttestation) error
}

type RevocationControl interface {
	CheckKustoRevocation(context.Context, RevocationCheck) error
}

type AuditCommitter interface {
	CommitKustoValidation(context.Context, AuditProof) (AuditProof, error)
}

// ReplayStore atomically reserves an idempotency key. Implementations coalesce
// an exact concurrent request and return ErrChangedReplay for changed reuse.
type ReplayStore interface {
	BeginKustoValidation(context.Context, string, string) (ReplayRecord, bool, error)
	CompleteKustoValidation(context.Context, string, ReplayRecord) error
	AbandonKustoValidation(context.Context, string, string)
}

type Clock interface{ Now() time.Time }

// Validator is the authority-bearing public Go boundary.
type Validator interface {
	Validate(context.Context, ValidateRequest) (ValidationAdmission, error)
}
