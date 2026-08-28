package kustovalidator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var (
	tokenPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	kustoNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	kustoPathPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}[.][A-Za-z_][A-Za-z0-9_]{0,127}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reasonPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	diagnosticPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,15}$`)
	testPattern       = regexp.MustCompile(`^Test[A-Za-z0-9]{3,127}$`)
)

var allowedOperators = []string{
	"count", "distinct", "extend", "filter", "limit", "order", "parse", "parse-where",
	"project", "project-away", "project-keep", "project-rename", "sort", "summarize", "take", "top", "union", "where",
}

var allowedFunctions = []string{
	"abs", "bin", "case", "coalesce", "endofday", "endofmonth", "endofweek", "format_datetime",
	"getmonth", "getyear", "iff", "indexof", "ipv4_compare", "ipv4_is_in_range", "isascii", "isempty",
	"isfinite", "isinf", "isnan", "isnotempty", "isnotnull", "isnull", "log", "max_of", "min_of",
	"round", "startofday", "startofmonth", "startofweek", "strcat", "strcmp", "strlen", "substring",
	"tobool", "todatetime", "todecimal", "todouble", "toint", "tolong", "tolower", "toreal", "tostring",
	"totimespan", "toupper", "trim", "trim_end", "trim_start",
}

var allowedAggregates = []string{
	"avg", "avgif", "count", "countif", "dcount", "dcountif", "max", "min", "sum", "sumif",
}

var prohibitedConstructs = []string{
	"control_command", "cross_cluster", "cross_database", "datatable", "dynamic_output", "entity_group",
	"evaluate", "execute", "external_data", "external_table", "fuzzy_union", "getschema", "invoke",
	"let_statement", "macro_expand", "materialized_view", "query_parameters", "restrict_statement",
	"set_statement", "stored_function", "stored_query_result", "wildcard_union",
}

func DecodeHelperRequest(input []byte) (HelperRequest, error) {
	var value HelperRequest
	if decodeExact(input, &value) != nil || validateHelperRequest(value) != nil {
		return HelperRequest{}, denied()
	}
	return clone(value), nil
}

func DecodeHelperResponse(input []byte) (HelperResponse, error) {
	var value HelperResponse
	if decodeExact(input, &value) != nil || validateHelperResponse(value) != nil {
		return HelperResponse{}, denied()
	}
	return clone(value), nil
}

func DecodeSemanticRegistry(input []byte) (SemanticRegistry, error) {
	var value SemanticRegistry
	if decodeExact(input, &value) != nil || validateRegistry(value) != nil {
		return SemanticRegistry{}, denied()
	}
	return clone(value), nil
}

func DecodeHelperAttestation(input []byte) (HelperAttestation, error) {
	var value HelperAttestation
	if decodeExact(input, &value) != nil || validateAttestation(value) != nil {
		return HelperAttestation{}, denied()
	}
	return clone(value), nil
}

func DecodePolicyDecision(input []byte) (PolicyDecision, error) {
	var value PolicyDecision
	if decodeExact(input, &value) != nil || validateDecision(value) != nil {
		return PolicyDecision{}, denied()
	}
	return clone(value), nil
}

func DecodeAuditProof(input []byte) (AuditProof, error) {
	var value AuditProof
	if decodeExact(input, &value) != nil || validateAudit(value) != nil {
		return AuditProof{}, denied()
	}
	return clone(value), nil
}

func DecodeRevocationEvidence(input []byte) (RevocationEvidence, error) {
	var value RevocationEvidence
	if decodeExact(input, &value) != nil || validateRevocation(value) != nil {
		return RevocationEvidence{}, denied()
	}
	return clone(value), nil
}

func DecodeDenialCorpus(input []byte) (DenialCorpus, error) {
	var value DenialCorpus
	if decodeExact(input, &value) != nil || value.SchemaVersion != DenialCorpusVersion ||
		value.ContractVersion != ContractVersion || len(value.Cases) < 24 || len(value.Cases) > 128 {
		return DenialCorpus{}, denied()
	}
	seen := make(map[string]struct{}, len(value.Cases))
	for _, item := range value.Cases {
		key := item.Class + "\x00" + item.Input
		if !tokenPattern.MatchString(item.Class) || item.Input == "" || len(item.Input) > 4096 ||
			strings.ContainsAny(item.Input, "\x00\r\n") || !reasonPattern.MatchString(item.Reason) ||
			!testPattern.MatchString(item.CoveredBy) {
			return DenialCorpus{}, denied()
		}
		if _, duplicate := seen[key]; duplicate {
			return DenialCorpus{}, denied()
		}
		seen[key] = struct{}{}
	}
	return clone(value), nil
}

func validateHelperRequest(value HelperRequest) error {
	if value.SchemaVersion != HelperRequestVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || value.Operation != "kusto.validate" ||
		value.Query == "" || len(value.Query) > MaximumQueryBytes || !utf8.ValidString(value.Query) ||
		strings.ContainsRune(value.Query, 0) || value.QueryDigest != QueryDigest(value.Query) ||
		!tokenPattern.MatchString(value.SourceID) || !validTokens(value.ResourceIDs, 1, MaximumTables) ||
		!validDigests(value.WorkspaceIdentityDigest, value.QualificationDigest, value.CapabilityDigest, value.SchemaDigest) ||
		validateSchema(value.Schema) != nil || value.SchemaDigest != SchemaDigest(value.Schema) ||
		validatePolicy(value.Policy) != nil || validateIdentity(value.HelperIdentityExpectation) != nil ||
		value.HelperIdentityExpectation.RegistryDigest != value.Policy.RegistryDigest ||
		value.RequestedRows == 0 || value.RequestedRows > value.Policy.MaximumRows || !validTimestamp(value.Deadline) ||
		value.RequestDigest != HelperRequestDigest(value) {
		return denied()
	}
	return nil
}

func validateHelperResponse(value HelperResponse) error {
	accepted := value.Outcome == "accepted"
	if value.SchemaVersion != HelperResponseVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validDigests(value.RequestDigest, value.SchemaDigest,
		value.RegistryDigest, value.ProvenanceDigest, value.ResponseDigest) ||
		!oneOf(value.Outcome, "accepted", "denied") || !validReasons(value.ReasonCodes) ||
		validateDiagnostics(value.Diagnostics) != nil || validateIdentity(value.HelperIdentity) != nil ||
		value.HelperIdentity.RegistryDigest != value.RegistryDigest || validateSemantic(value.Semantic) != nil ||
		validateOutputColumns(value.OutputColumns) != nil || value.ResponseDigest != HelperResponseDigest(value) {
		return denied()
	}
	if accepted {
		if len(value.ReasonCodes) != 0 || len(value.Diagnostics) != 0 || value.CanonicalKQL == "" ||
			len(value.CanonicalKQL) > MaximumCanonicalBytes || !utf8.ValidString(value.CanonicalKQL) ||
			strings.ContainsRune(value.CanonicalKQL, 0) || value.CanonicalKQLDigest != CanonicalKQLDigest(value.CanonicalKQL) ||
			!validDigests(value.OriginalTreeDigest, value.BoundedTreeDigest, value.CanonicalKQLDigest) ||
			value.TerminalTake == 0 || value.TerminalTake > MaximumRows || len(value.Semantic.Tables) == 0 ||
			len(value.OutputColumns) == 0 {
			return denied()
		}
	} else if len(value.ReasonCodes) == 0 || value.CanonicalKQL != "" || value.CanonicalKQLDigest != "" ||
		value.OriginalTreeDigest != "" || value.BoundedTreeDigest != "" || value.TerminalTake != 0 ||
		len(value.Semantic.Tables)+len(value.Semantic.Columns)+len(value.Semantic.Operators)+len(value.Semantic.Functions) != 0 ||
		len(value.OutputColumns) != 0 {
		return denied()
	}
	return nil
}

func validateRegistry(value SemanticRegistry) error {
	if value.SchemaVersion != RegistryVersion || value.ContractVersion != ContractVersion ||
		value.ValidatorVersion != ValidatorVersion || !slices.Equal(value.AllowedOperators, allowedOperators) ||
		!slices.Equal(value.AllowedFunctions, allowedFunctions) || !slices.Equal(value.AllowedAggregates, allowedAggregates) ||
		!slices.Equal(value.ProhibitedConstructs, prohibitedConstructs) || value.StoredFunctionsAllowed ||
		value.EvaluateAllowed || value.ExternalDataAllowed || value.CrossClusterAllowed || value.DynamicOutputAllowed ||
		value.Digest != SemanticRegistryDigest(value) {
		return denied()
	}
	return nil
}

func validateAttestation(value HelperAttestation) error {
	observed, observedOK := parseTimestamp(value.ObservedAt)
	validUntil, validUntilOK := parseTimestamp(value.ValidUntil)
	if value.SchemaVersion != AttestationVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.AttestationID) || !observedOK || !validUntilOK || !observed.Before(validUntil) ||
		validUntil.Sub(observed) > 30*24*time.Hour || validateIdentity(value.Identity) != nil ||
		value.KustoLanguageVersion != "12.4.1" || value.DotnetSDKVersion != "10.0.400" ||
		value.DotnetRuntimeVersion != "10.0.11" || !validDigests(value.ManifestDigest, value.SBOMDigest, value.ProvenanceDigest) ||
		!value.NetworkDenied || !slices.Equal(value.CredentialClasses, []string{"none"}) || !value.Reproducible ||
		value.Digest != HelperAttestationDigest(value) {
		return denied()
	}
	return nil
}

func validateDecision(value PolicyDecision) error {
	observed, observedOK := parseTimestamp(value.ObservedAt)
	validUntil, validUntilOK := parseTimestamp(value.ValidUntil)
	if value.SchemaVersion != PolicyDecisionVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.DecisionID) || !uuidPattern.MatchString(value.QueryID) ||
		!oneOf(value.Outcome, "accepted", "denied") || !validReasons(value.ReasonCodes) ||
		(value.Outcome == "accepted" && len(value.ReasonCodes) != 0) || (value.Outcome == "denied" && len(value.ReasonCodes) == 0) ||
		!uuidPattern.MatchString(value.ActorID) || !validDigests(value.ScopeDigest, value.RequestDigest, value.ResponseDigest,
		value.CapabilityDigest, value.SchemaDigest, value.RegistryDigest, value.HelperAttestationDigest,
		value.PolicyDecisionDigest, value.AuditReservationDigest, value.Digest) || !observedOK || !validUntilOK ||
		!observed.Before(validUntil) || validUntil.Sub(observed) > 5*time.Minute || value.Digest != PolicyDecisionDigest(value) {
		return denied()
	}
	return nil
}

func validateAudit(value AuditProof) error {
	if value.SchemaVersion != AuditProofVersion || value.ContractVersion != ContractVersion ||
		!tokenPattern.MatchString(value.Event) || !oneOf(value.Outcome, "accepted", "denied", "revoked", "unavailable") ||
		!validReasons(value.ReasonCodes) || !uuidPattern.MatchString(value.QueryID) || !uuidPattern.MatchString(value.ActorID) ||
		!validDigests(value.ScopeDigest, value.RequestDigest, value.ResponseDigest, value.RegistryDigest,
			value.HelperAttestationDigest, value.PolicyDecisionDigest, value.AuditReservationDigest, value.AuditRecordDigest) ||
		value.QueryTextExposed || value.LiteralExposed || value.SchemaNameExposed || value.WorkspaceExposed ||
		value.CredentialExposed || value.ExecutablePathExposed || value.StderrExposed {
		return denied()
	}
	return nil
}

func validateRevocation(value RevocationEvidence) error {
	if value.SchemaVersion != RevocationVersion || value.ContractVersion != ContractVersion ||
		!validDigests(value.DecisionDigest, value.HelperAttestationDigest, value.RevocationDigest, value.AuditReservationDigest) ||
		!reasonPattern.MatchString(value.ReasonCode) || !validTimestamp(value.ObservedAt) ||
		value.ValidationPermitted || value.ExecutionPermitted {
		return denied()
	}
	return nil
}

func validateSchema(value SchemaBinding) error {
	observed, observedOK := parseTimestamp(value.ObservedAt)
	validUntil, validUntilOK := parseTimestamp(value.ValidUntil)
	if value.Database != "coh_workspace" || !observedOK || !validUntilOK || !observed.Before(validUntil) ||
		validUntil.Sub(observed) > 24*time.Hour || len(value.Tables) == 0 || len(value.Tables) > MaximumTables {
		return denied()
	}
	totalColumns, previousTable := 0, ""
	for _, table := range value.Tables {
		if !kustoNamePattern.MatchString(table.Name) || table.Name <= previousTable || len(table.Columns) == 0 {
			return denied()
		}
		previousColumn := ""
		for _, column := range table.Columns {
			if !kustoNamePattern.MatchString(column.Name) || column.Name <= previousColumn || !oneOf(column.Type,
				"bool", "datetime", "decimal", "guid", "int", "long", "real", "string", "timespan") {
				return denied()
			}
			previousColumn, totalColumns = column.Name, totalColumns+1
		}
		previousTable = table.Name
	}
	if totalColumns > MaximumColumns {
		return denied()
	}
	return nil
}

func validatePolicy(value Policy) error {
	if value.Profile != "coh-kql-v1" || !digestPattern.MatchString(value.RegistryDigest) ||
		value.MaximumRows == 0 || value.MaximumRows > MaximumRows || value.MaximumQueryBytes == 0 ||
		value.MaximumQueryBytes > MaximumQueryBytes || value.MaximumSyntaxNodes == 0 || value.MaximumSyntaxNodes > 8192 ||
		value.MaximumSyntaxDepth == 0 || value.MaximumSyntaxDepth > 64 || value.MaximumOperators == 0 || value.MaximumOperators > 64 ||
		value.MaximumOutputColumns == 0 || value.MaximumOutputColumns > 256 || value.MaximumAggregates == 0 ||
		value.MaximumAggregates > 64 || value.MaximumUnionOperands == 0 || value.MaximumUnionOperands > 32 {
		return denied()
	}
	return nil
}

func validateIdentity(value HelperIdentity) error {
	if value.Name != "coh-kusto-validator" || value.Version != ValidatorVersion ||
		!oneOf(value.RID, "linux-arm64", "linux-x64", "osx-arm64") ||
		!validDigests(value.ArtifactDigest, value.PackageClosureDigest, value.RuntimeDigest, value.RegistryDigest) {
		return denied()
	}
	return nil
}

func validateDiagnostics(values []Diagnostic) error {
	if len(values) > MaximumDiagnostics {
		return denied()
	}
	previous := ""
	for _, value := range values {
		key := value.Code + "\x00" + value.Class
		if !diagnosticPattern.MatchString(value.Code) || value.Severity != "error" ||
			!reasonPattern.MatchString(value.Class) || key <= previous {
			return denied()
		}
		previous = key
	}
	return nil
}

func validateSemantic(value SemanticInventory) error {
	if !validKustoNames(value.Tables, 0, MaximumTables) || !validKustoPaths(value.Columns, 0, MaximumColumns) ||
		!validTokens(value.Operators, 0, MaximumRegistryEntries) || !validTokens(value.Functions, 0, MaximumRegistryEntries) {
		return denied()
	}
	return nil
}

func validateOutputColumns(values []OutputColumn) error {
	if len(values) > 256 {
		return denied()
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !kustoNamePattern.MatchString(value.Name) || !oneOf(value.Type,
			"bool", "datetime", "decimal", "guid", "int", "long", "real", "string", "timespan") {
			return denied()
		}
		if _, duplicate := seen[value.Name]; duplicate {
			return denied()
		}
		seen[value.Name] = struct{}{}
	}
	return nil
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > MaximumDocumentBytes {
		return denied()
	}
	unique, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return denied()
	}
	encoded, err := json.Marshal(unique)
	if err != nil {
		return denied()
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return denied()
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return denied()
	}
	return nil
}

func HelperRequestDigest(value HelperRequest) string {
	value.RequestDigest = ""
	return digestValue("COH-KUSTO-HELPER-REQUEST-V1\x00", value)
}

func HelperResponseDigest(value HelperResponse) string {
	value.ResponseDigest = ""
	return digestValue("COH-KUSTO-HELPER-RESPONSE-V1\x00", value)
}

func SemanticRegistryDigest(value SemanticRegistry) string {
	value.Digest = ""
	return digestValue("COH-KUSTO-SEMANTIC-REGISTRY-V1\x00", value)
}

func HelperAttestationDigest(value HelperAttestation) string {
	value.Digest = ""
	return digestValue("COH-KUSTO-HELPER-ATTESTATION-V1\x00", value)
}

func PolicyDecisionDigest(value PolicyDecision) string {
	value.Digest = ""
	return digestValue("COH-KUSTO-VALIDATOR-DECISION-V1\x00", value)
}

func SchemaDigest(value SchemaBinding) string {
	return digestValue("COH-KUSTO-SCHEMA-BINDING-V1\x00", value)
}

func QueryDigest(value string) string { return digestBytes("COH-KUSTO-QUERY-V1\x00", []byte(value)) }

func CanonicalKQLDigest(value string) string {
	return digestBytes("COH-KUSTO-CANONICAL-KQL-V1\x00", []byte(value))
}

func digestValue(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	return digestBytes(domain, encoded)
}

func digestBytes(domain string, value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func validTokens(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validKustoNames(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !kustoNamePattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validKustoPaths(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !kustoPathPattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validReasons(values []string) bool {
	if len(values) > MaximumReasons || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !reasonPattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validTimestamp(value string) bool { _, ok := parseTimestamp(value); return ok }

func parseTimestamp(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil && strings.HasSuffix(value, "Z") && parsed.Format(time.RFC3339Nano) == value
}

func oneOf(value string, values ...string) bool { return slices.Contains(values, value) }

func clone[T any](value T) T {
	encoded, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(encoded, &result)
	return result
}
