package sigmacompiler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var ErrContractDenied = errors.New("pySigma compiler contract denied")

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	fieldPattern      = regexp.MustCompile(`^[A-Za-z_@][A-Za-z0-9_.@-]{0,127}$`)
	reasonPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	diagnosticPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,15}$`)
	testPattern       = regexp.MustCompile(`^Test[A-Za-z0-9]{3,127}$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

var targetMatrix = []TargetBinding{
	{Target: "elastic", NativeLanguage: "esql", BackendPackage: "pysigma-backend-elasticsearch", BackendVersion: "2.1.0", BackendCommit: "5bf3529d1450e46b6a937ad29ecf0e122fbadf9d", BackendClass: "ESQLBackend", OutputFormat: "default"},
	{Target: "security-onion", NativeLanguage: "security-onion-oql", BackendPackage: "none", BackendVersion: "none", BackendCommit: "none", BackendClass: "none", OutputFormat: "none"},
	{Target: "sentinel", NativeLanguage: "kql", BackendPackage: "pysigma-backend-kusto", BackendVersion: "1.0.1", BackendCommit: "c83f737a39f1084f30022150482f8dbbc035034b", BackendClass: "KustoBackend", OutputFormat: "default"},
	{Target: "splunk", NativeLanguage: "spl", BackendPackage: "pysigma-backend-splunk", BackendVersion: "2.1.0", BackendCommit: "68a5e382f1d57a14337c6e66022af34da1e3bfe6", BackendClass: "SplunkBackend", OutputFormat: "default"},
}

func DecodeCompileRequest(input []byte) (CompileRequest, error) {
	var value CompileRequest
	if decodeExact(input, &value) != nil || validateRequest(value) != nil {
		return CompileRequest{}, ErrContractDenied
	}
	return clone(value), nil
}

func DecodeCompileResponse(input []byte) (CompileResponse, error) {
	var value CompileResponse
	if decodeExact(input, &value) != nil || validateResponse(value) != nil {
		return CompileResponse{}, ErrContractDenied
	}
	return clone(value), nil
}

func DecodeCapabilitySnapshot(input []byte) (CapabilitySnapshot, error) {
	var value CapabilitySnapshot
	if decodeExact(input, &value) != nil || validateCapability(value) != nil {
		return CapabilitySnapshot{}, ErrContractDenied
	}
	return clone(value), nil
}

func DecodeHelperAttestation(input []byte) (HelperAttestation, error) {
	var value HelperAttestation
	if decodeExact(input, &value) != nil || validateAttestation(value) != nil {
		return HelperAttestation{}, ErrContractDenied
	}
	return clone(value), nil
}

func DecodeProvenanceReceipt(input []byte) (ProvenanceReceipt, error) {
	var value ProvenanceReceipt
	if decodeExact(input, &value) != nil || validateProvenance(value) != nil {
		return ProvenanceReceipt{}, ErrContractDenied
	}
	return clone(value), nil
}

func DecodeDenialCorpus(input []byte) (DenialCorpus, error) {
	var value DenialCorpus
	if decodeExact(input, &value) != nil || validateDenialCorpus(value) != nil {
		return DenialCorpus{}, ErrContractDenied
	}
	return clone(value), nil
}

func DecodeRedactedTrace(input []byte) (RedactedTrace, error) {
	var value RedactedTrace
	if decodeExact(input, &value) != nil || validateRedactedTrace(value) != nil {
		return RedactedTrace{}, ErrContractDenied
	}
	return clone(value), nil
}

func ValidateExchange(request CompileRequest, response CompileResponse) error {
	if validateRequest(request) != nil || validateResponse(response) != nil ||
		response.RequestID != request.RequestID || response.RequestDigest != request.RequestDigest ||
		response.Target != request.Target || response.SigmaDigest != request.SigmaDigest ||
		response.MappingDigest != request.Mapping.MappingDigest ||
		response.TargetSchemaDigest != request.Mapping.TargetSchemaDigest ||
		response.HelperIdentity != request.HelperIdentityExpectation {
		return ErrContractDenied
	}
	return nil
}

func validateRequest(value CompileRequest) error {
	if value.SchemaVersion != RequestVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || value.Operation != "sigma.compile" ||
		value.SigmaProfile != SigmaProfile || value.SigmaYAML == "" || len(value.SigmaYAML) > MaximumSigmaBytes ||
		!utf8.ValidString(value.SigmaYAML) || strings.ContainsRune(value.SigmaYAML, 0) ||
		value.SigmaDigest != SigmaDigest(value.SigmaYAML) || validateTarget(value.Target) != nil ||
		value.Target.Target == "security-onion" || validateMapping(value.Mapping) != nil ||
		!validDigests(value.CapabilityDigest, value.QualificationDigest) || validatePolicy(value.Policy) != nil ||
		validateIdentity(value.HelperIdentityExpectation) != nil || !validTimestamp(value.Deadline) ||
		value.RequestDigest != CompileRequestDigest(value) {
		return ErrContractDenied
	}
	return nil
}

func validateResponse(value CompileResponse) error {
	compiled := value.Outcome == "compiled_untrusted"
	if value.SchemaVersion != ResponseVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validDigests(value.RequestDigest, value.SigmaDigest,
		value.MappingDigest, value.TargetSchemaDigest, value.ProvenanceDigest, value.ResponseDigest) ||
		!oneOf(value.Outcome, "compiled_untrusted", "needs_mapping", "unsupported", "denied") ||
		!validReasons(value.ReasonCodes) || validateDiagnostics(value.Diagnostics) != nil ||
		validateTarget(value.Target) != nil || validateIdentity(value.HelperIdentity) != nil ||
		value.ResponseDigest != CompileResponseDigest(value) {
		return ErrContractDenied
	}
	if compiled {
		if len(value.ReasonCodes) != 0 || len(value.Diagnostics) != 0 || value.Target.Target == "security-onion" ||
			value.NativeQuery == "" || len(value.NativeQuery) > MaximumNativeBytes || !utf8.ValidString(value.NativeQuery) ||
			strings.ContainsRune(value.NativeQuery, 0) || value.NativeQueryDigest != NativeQueryDigest(value.NativeQuery) {
			return ErrContractDenied
		}
	} else if len(value.ReasonCodes) == 0 || value.NativeQuery != "" || value.NativeQueryDigest != "" {
		return ErrContractDenied
	}
	return nil
}

func validateTarget(value TargetBinding) error {
	if !slices.Contains(targetMatrix, value) {
		return ErrContractDenied
	}
	if value.BackendCommit != "none" && !commitPattern.MatchString(value.BackendCommit) {
		return ErrContractDenied
	}
	return nil
}

func validateMapping(value MappingBinding) error {
	if !uuidPattern.MatchString(value.MappingID) || value.Revision == 0 ||
		!tokenPattern.MatchString(value.TargetResource) || validateLogsource(value.Logsource) != nil ||
		len(value.Fields) == 0 || len(value.Fields) > MaximumFieldMappings ||
		!validDigests(value.SourceSchemaDigest, value.TargetSchemaDigest, value.MappingDigest) ||
		value.MappingDigest != MappingDigest(value) {
		return ErrContractDenied
	}
	previousSource := ""
	seenTargets := make(map[string]struct{}, len(value.Fields))
	for _, field := range value.Fields {
		if !fieldPattern.MatchString(field.Source) || !fieldPattern.MatchString(field.Target) ||
			!oneOf(field.DataType, "bool", "datetime", "float", "integer", "ip", "keyword", "string") ||
			field.Source <= previousSource {
			return ErrContractDenied
		}
		if _, duplicate := seenTargets[field.Target]; duplicate {
			return ErrContractDenied
		}
		previousSource = field.Source
		seenTargets[field.Target] = struct{}{}
	}
	return nil
}

func validateLogsource(value Logsource) error {
	if value.Category == "" || value.Product == "" {
		return ErrContractDenied
	}
	for _, item := range []string{value.Category, value.Product, value.Service} {
		if item != "" && !tokenPattern.MatchString(item) {
			return ErrContractDenied
		}
	}
	if len(value.Definition) > 256 || !utf8.ValidString(value.Definition) || strings.ContainsAny(value.Definition, "\x00\r\n") {
		return ErrContractDenied
	}
	return nil
}

func validatePolicy(value Policy) error {
	if value.Profile != SigmaProfile || value.MaximumSigmaBytes == 0 || value.MaximumSigmaBytes > MaximumSigmaBytes ||
		value.MaximumYAMLNodes == 0 || value.MaximumYAMLNodes > 4096 || value.MaximumYAMLDepth == 0 || value.MaximumYAMLDepth > 32 ||
		value.MaximumMappingEntries == 0 || value.MaximumMappingEntries > 2048 || value.MaximumSequenceEntries == 0 || value.MaximumSequenceEntries > 2048 ||
		value.MaximumScalarBytes == 0 || value.MaximumScalarBytes > 16384 || value.MaximumScalars == 0 || value.MaximumScalars > 4096 ||
		value.MaximumSelections == 0 || value.MaximumSelections > 64 || value.MaximumDetectionItems == 0 || value.MaximumDetectionItems > 512 ||
		value.MaximumDetectionValues == 0 || value.MaximumDetectionValues > 2048 || value.MaximumConditionTokens == 0 || value.MaximumConditionTokens > 512 ||
		value.MaximumConditionDepth == 0 || value.MaximumConditionDepth > 32 || value.MaximumExpandedTerms == 0 || value.MaximumExpandedTerms > 2048 ||
		value.MaximumNativeQueryBytes == 0 || value.MaximumNativeQueryBytes > MaximumNativeBytes {
		return ErrContractDenied
	}
	return nil
}

func validateIdentity(value HelperIdentity) error {
	if value.Name != "coh-pysigma-helper" || value.Version != CompilerVersion ||
		!oneOf(value.RID, "linux-arm64", "linux-x64", "osx-arm64") ||
		!validDigests(value.ArtifactDigest, value.PackageClosureDigest, value.RuntimeDigest,
			value.BackendMatrixDigest, value.ProfileDigest) {
		return ErrContractDenied
	}
	return nil
}

func validateCapability(value CapabilitySnapshot) error {
	observed, observedOK := parseTimestamp(value.ObservedAt)
	validUntil, validOK := parseTimestamp(value.ValidUntil)
	if value.SchemaVersion != CapabilityVersion || value.ContractVersion != ContractVersion ||
		value.SigmaProfile != SigmaProfile || value.CompilerVersion != CompilerVersion || !observedOK || !validOK ||
		!observed.Before(validUntil) || validUntil.Sub(observed) > 30*24*time.Hour ||
		len(value.BackendCapabilities) != len(targetMatrix) || validatePolicy(value.Policy) != nil ||
		!validDigests(value.BackendMatrixDigest, value.Digest) || value.Digest != CapabilitySnapshotDigest(value) {
		return ErrContractDenied
	}
	for index, item := range value.BackendCapabilities {
		target := targetMatrix[index]
		if item.Target != target.Target || item.NativeLanguage != target.NativeLanguage ||
			item.BackendPackage != target.BackendPackage || item.BackendVersion != target.BackendVersion ||
			item.BackendCommit != target.BackendCommit || item.BackendClass != target.BackendClass ||
			item.OutputFormat != target.OutputFormat || !oneOf(item.Qualification, "candidate", "unavailable") ||
			(item.Target == "security-onion" && (item.Qualification != "unavailable" || item.ReasonCode != "native_contract_mismatch")) ||
			(item.Target != "security-onion" && (item.Qualification != "candidate" || item.ReasonCode != "")) {
			return ErrContractDenied
		}
	}
	return nil
}

func validateAttestation(value HelperAttestation) error {
	observed, observedOK := parseTimestamp(value.ObservedAt)
	validUntil, validOK := parseTimestamp(value.ValidUntil)
	if value.SchemaVersion != AttestationVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.AttestationID) || !observedOK || !validOK || !observed.Before(validUntil) ||
		validUntil.Sub(observed) > 30*24*time.Hour || validateIdentity(value.Identity) != nil ||
		value.PythonVersion != "3.13.15" || value.PySigmaVersion != "1.5.0" || value.PyInstallerVersion != "6.22.2" ||
		!validDigests(value.ManifestDigest, value.SBOMDigest, value.ProvenanceDigest, value.Digest) ||
		!value.NetworkDenied || !slices.Equal(value.CredentialClasses, []string{"none"}) ||
		!value.AmbientPluginsDenied || !value.ExternalSourcesDenied || !value.SkipUnsupportedDenied || !value.Reproducible ||
		value.Digest != HelperAttestationDigest(value) {
		return ErrContractDenied
	}
	return nil
}

func validateProvenance(value ProvenanceReceipt) error {
	if value.SchemaVersion != ProvenanceVersion || value.ContractVersion != ContractVersion ||
		!validDigests(value.RequestDigest, value.ResponseDigest, value.SigmaDigest, value.MappingDigest,
			value.TargetSchemaDigest, value.NativeQueryDigest, value.HelperAttestationDigest, value.CapabilityDigest,
			value.QualificationDigest, value.PolicyDigest, value.AuditReservationDigest, value.Digest) ||
		value.State != "compiled_untrusted" || value.Digest != ProvenanceReceiptDigest(value) {
		return ErrContractDenied
	}
	return nil
}

func validateDenialCorpus(value DenialCorpus) error {
	if value.SchemaVersion != DenialCorpusVersion || value.ContractVersion != ContractVersion ||
		len(value.Cases) < 12 || len(value.Cases) > MaximumDenialCases {
		return ErrContractDenied
	}
	previous := ""
	for _, item := range value.Cases {
		key := item.Class + "\x00" + item.Mutation
		if !tokenPattern.MatchString(item.Class) || item.Mutation == "" || len(item.Mutation) > 128 ||
			!oneOf(item.Outcome, "needs_mapping", "unsupported", "denied") || !reasonPattern.MatchString(item.Reason) ||
			!testPattern.MatchString(item.CoveredBy) || key <= previous {
			return ErrContractDenied
		}
		previous = key
	}
	return nil
}

func validateRedactedTrace(value RedactedTrace) error {
	if value.SchemaVersion != RedactedTraceVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.TraceID) || len(value.Events) == 0 || len(value.Events) > MaximumTraceEvents ||
		value.NativeTextExposed || value.SigmaTextExposed || value.FieldNameExposed || value.CredentialExposed || value.PathExposed {
		return ErrContractDenied
	}
	for index, event := range value.Events {
		if event.Sequence != uint32(index+1) || !tokenPattern.MatchString(event.Phase) ||
			!oneOf(event.Outcome, "accepted", "denied", "unavailable") || !validReasons(event.ReasonCodes) ||
			!digestPattern.MatchString(event.RequestDigest) ||
			(event.Outcome == "accepted" && len(event.ReasonCodes) != 0) ||
			(event.Outcome != "accepted" && len(event.ReasonCodes) == 0) {
			return ErrContractDenied
		}
	}
	return nil
}

func validateDiagnostics(values []Diagnostic) error {
	if len(values) > MaximumDiagnostics {
		return ErrContractDenied
	}
	previous := ""
	for _, value := range values {
		key := value.Code + "\x00" + value.Class + "\x00" + value.Location
		if !diagnosticPattern.MatchString(value.Code) || value.Severity != "error" ||
			!reasonPattern.MatchString(value.Class) || !tokenPattern.MatchString(value.Location) || key <= previous {
			return ErrContractDenied
		}
		previous = key
	}
	return nil
}

func validReasons(values []string) bool {
	if len(values) > MaximumReasonCodes || !slices.IsSorted(values) {
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

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > MaximumDocumentBytes {
		return ErrContractDenied
	}
	unique, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return ErrContractDenied
	}
	encoded, err := json.Marshal(unique)
	if err != nil {
		return ErrContractDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return ErrContractDenied
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrContractDenied
	}
	return nil
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
