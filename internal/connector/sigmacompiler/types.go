// Package sigmacompiler defines the closed credentialless pySigma helper
// protocol. Authority-bearing lifecycle behavior is added by the Go service.
package sigmacompiler

const (
	ContractVersion      = "1.0.0"
	CompilerVersion      = "pysigma-1.5.0-coh-1.0.0"
	SigmaProfile         = "sigma-basic-2.1.0-coh-v1"
	RequestVersion       = "coh.pysigma-helper-request/v1"
	ResponseVersion      = "coh.pysigma-helper-response/v1"
	CapabilityVersion    = "coh.pysigma-capability/v1"
	AttestationVersion   = "coh.pysigma-helper-attestation/v1"
	ProvenanceVersion    = "coh.pysigma-provenance/v1"
	DenialCorpusVersion  = "coh.pysigma-denials/v1"
	RedactedTraceVersion = "coh.pysigma-redacted-trace/v1"
	MaximumDocumentBytes = 1 << 20
	MaximumSigmaBytes    = 128 << 10
	MaximumNativeBytes   = 256 << 10
	MaximumDiagnostics   = 32
	MaximumReasonCodes   = 32
	MaximumFieldMappings = 256
	MaximumTraceEvents   = 64
	MaximumDenialCases   = 128
)

type CompileRequest struct {
	SchemaVersion             string         `json:"schema_version"`
	ContractVersion           string         `json:"contract_version"`
	RequestID                 string         `json:"request_id"`
	Operation                 string         `json:"operation"`
	SigmaYAML                 string         `json:"sigma_yaml"`
	SigmaDigest               string         `json:"sigma_digest"`
	SigmaProfile              string         `json:"sigma_profile"`
	Target                    TargetBinding  `json:"target"`
	Mapping                   MappingBinding `json:"mapping"`
	CapabilityDigest          string         `json:"capability_digest"`
	QualificationDigest       string         `json:"qualification_digest"`
	Policy                    Policy         `json:"policy"`
	HelperIdentityExpectation HelperIdentity `json:"helper_identity_expectation"`
	Deadline                  string         `json:"deadline"`
	RequestDigest             string         `json:"request_digest"`
}

type TargetBinding struct {
	Target         string `json:"target"`
	NativeLanguage string `json:"native_language"`
	BackendPackage string `json:"backend_package"`
	BackendVersion string `json:"backend_version"`
	BackendCommit  string `json:"backend_commit"`
	BackendClass   string `json:"backend_class"`
	OutputFormat   string `json:"output_format"`
}

type MappingBinding struct {
	MappingID          string         `json:"mapping_id"`
	Revision           uint64         `json:"revision"`
	TargetResource     string         `json:"target_resource"`
	Logsource          Logsource      `json:"logsource"`
	Fields             []FieldMapping `json:"fields"`
	SourceSchemaDigest string         `json:"source_schema_digest"`
	TargetSchemaDigest string         `json:"target_schema_digest"`
	MappingDigest      string         `json:"mapping_digest"`
}

type Logsource struct {
	Category   string `json:"category"`
	Product    string `json:"product"`
	Service    string `json:"service"`
	Definition string `json:"definition"`
}

type FieldMapping struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	DataType string `json:"data_type"`
}

type Policy struct {
	Profile                 string `json:"profile"`
	MaximumSigmaBytes       uint32 `json:"maximum_sigma_bytes"`
	MaximumYAMLNodes        uint32 `json:"maximum_yaml_nodes"`
	MaximumYAMLDepth        uint32 `json:"maximum_yaml_depth"`
	MaximumMappingEntries   uint32 `json:"maximum_mapping_entries"`
	MaximumSequenceEntries  uint32 `json:"maximum_sequence_entries"`
	MaximumScalarBytes      uint32 `json:"maximum_scalar_bytes"`
	MaximumScalars          uint32 `json:"maximum_scalars"`
	MaximumSelections       uint32 `json:"maximum_selections"`
	MaximumDetectionItems   uint32 `json:"maximum_detection_items"`
	MaximumDetectionValues  uint32 `json:"maximum_detection_values"`
	MaximumConditionTokens  uint32 `json:"maximum_condition_tokens"`
	MaximumConditionDepth   uint32 `json:"maximum_condition_depth"`
	MaximumExpandedTerms    uint32 `json:"maximum_expanded_terms"`
	MaximumNativeQueryBytes uint32 `json:"maximum_native_query_bytes"`
}

type HelperIdentity struct {
	Name                 string `json:"name"`
	Version              string `json:"version"`
	RID                  string `json:"rid"`
	ArtifactDigest       string `json:"artifact_digest"`
	PackageClosureDigest string `json:"package_closure_digest"`
	RuntimeDigest        string `json:"runtime_digest"`
	BackendMatrixDigest  string `json:"backend_matrix_digest"`
	ProfileDigest        string `json:"profile_digest"`
}

type CompileResponse struct {
	SchemaVersion      string         `json:"schema_version"`
	ContractVersion    string         `json:"contract_version"`
	RequestID          string         `json:"request_id"`
	RequestDigest      string         `json:"request_digest"`
	Outcome            string         `json:"outcome"`
	ReasonCodes        []string       `json:"reason_codes"`
	Diagnostics        []Diagnostic   `json:"diagnostics"`
	Target             TargetBinding  `json:"target"`
	SigmaDigest        string         `json:"sigma_digest"`
	MappingDigest      string         `json:"mapping_digest"`
	TargetSchemaDigest string         `json:"target_schema_digest"`
	NativeQuery        string         `json:"native_query"`
	NativeQueryDigest  string         `json:"native_query_digest"`
	HelperIdentity     HelperIdentity `json:"helper_identity"`
	ProvenanceDigest   string         `json:"provenance_digest"`
	ResponseDigest     string         `json:"response_digest"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Class    string `json:"class"`
	Location string `json:"location"`
}

type CapabilitySnapshot struct {
	SchemaVersion       string              `json:"schema_version"`
	ContractVersion     string              `json:"contract_version"`
	ObservedAt          string              `json:"observed_at"`
	ValidUntil          string              `json:"valid_until"`
	SigmaProfile        string              `json:"sigma_profile"`
	CompilerVersion     string              `json:"compiler_version"`
	BackendCapabilities []BackendCapability `json:"backend_capabilities"`
	Policy              Policy              `json:"policy"`
	BackendMatrixDigest string              `json:"backend_matrix_digest"`
	Digest              string              `json:"digest"`
}

type BackendCapability struct {
	Target         string `json:"target"`
	NativeLanguage string `json:"native_language"`
	BackendPackage string `json:"backend_package"`
	BackendVersion string `json:"backend_version"`
	BackendCommit  string `json:"backend_commit"`
	BackendClass   string `json:"backend_class"`
	OutputFormat   string `json:"output_format"`
	Qualification  string `json:"qualification"`
	ReasonCode     string `json:"reason_code"`
}

type HelperAttestation struct {
	SchemaVersion         string         `json:"schema_version"`
	ContractVersion       string         `json:"contract_version"`
	AttestationID         string         `json:"attestation_id"`
	ObservedAt            string         `json:"observed_at"`
	ValidUntil            string         `json:"valid_until"`
	Identity              HelperIdentity `json:"identity"`
	PythonVersion         string         `json:"python_version"`
	PySigmaVersion        string         `json:"pysigma_version"`
	PyInstallerVersion    string         `json:"pyinstaller_version"`
	ManifestDigest        string         `json:"manifest_digest"`
	SBOMDigest            string         `json:"sbom_digest"`
	ProvenanceDigest      string         `json:"provenance_digest"`
	NetworkDenied         bool           `json:"network_denied"`
	CredentialClasses     []string       `json:"credential_classes"`
	AmbientPluginsDenied  bool           `json:"ambient_plugins_denied"`
	ExternalSourcesDenied bool           `json:"external_sources_denied"`
	SkipUnsupportedDenied bool           `json:"skip_unsupported_denied"`
	Reproducible          bool           `json:"reproducible"`
	Digest                string         `json:"digest"`
}

type ProvenanceReceipt struct {
	SchemaVersion           string `json:"schema_version"`
	ContractVersion         string `json:"contract_version"`
	RequestDigest           string `json:"request_digest"`
	ResponseDigest          string `json:"response_digest"`
	SigmaDigest             string `json:"sigma_digest"`
	MappingDigest           string `json:"mapping_digest"`
	TargetSchemaDigest      string `json:"target_schema_digest"`
	NativeQueryDigest       string `json:"native_query_digest"`
	HelperAttestationDigest string `json:"helper_attestation_digest"`
	CapabilityDigest        string `json:"capability_digest"`
	QualificationDigest     string `json:"qualification_digest"`
	PolicyDigest            string `json:"policy_digest"`
	AuditReservationDigest  string `json:"audit_reservation_digest"`
	State                   string `json:"state"`
	Digest                  string `json:"digest"`
}

type DenialCorpus struct {
	SchemaVersion   string       `json:"schema_version"`
	ContractVersion string       `json:"contract_version"`
	Cases           []DenialCase `json:"cases"`
}

type DenialCase struct {
	Class     string `json:"class"`
	Mutation  string `json:"mutation"`
	Outcome   string `json:"outcome"`
	Reason    string `json:"reason"`
	CoveredBy string `json:"covered_by"`
}

type RedactedTrace struct {
	SchemaVersion     string       `json:"schema_version"`
	ContractVersion   string       `json:"contract_version"`
	TraceID           string       `json:"trace_id"`
	Events            []TraceEvent `json:"events"`
	NativeTextExposed bool         `json:"native_text_exposed"`
	SigmaTextExposed  bool         `json:"sigma_text_exposed"`
	FieldNameExposed  bool         `json:"field_name_exposed"`
	CredentialExposed bool         `json:"credential_exposed"`
	PathExposed       bool         `json:"path_exposed"`
}

type TraceEvent struct {
	Sequence      uint32   `json:"sequence"`
	Phase         string   `json:"phase"`
	Outcome       string   `json:"outcome"`
	ReasonCodes   []string `json:"reason_codes"`
	RequestDigest string   `json:"request_digest"`
}
