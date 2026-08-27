package evidencelifecycle

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func CanonicalCommand(value Command) ([]byte, error) {
	if err := validateCommandShape(value); err != nil {
		return nil, err
	}
	return canonicalValue(value)
}

func CanonicalManifest(value ExportManifest) ([]byte, error) {
	if err := ValidateExportManifest(value); err != nil {
		return nil, err
	}
	return canonicalValue(value)
}

func CanonicalDetachedSignature(value DetachedSignature) ([]byte, error) {
	if err := ValidateDetachedSignature(value); err != nil {
		return nil, err
	}
	return canonicalValue(value)
}

func IntentBindingDigest(value Command) (string, error) {
	canonical, err := CanonicalCommand(value)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-INTENT-V1\x00", canonical), nil
}

func CommandBindingDigest(value Command) (string, error) {
	canonical, err := CanonicalCommand(value)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-COMMAND-V1\x00", canonical), nil
}

func IdempotencyBindingDigest(value string) (string, error) {
	if !validOpaque(value, 1, 256) {
		return "", newError(InvalidInput, "idempotency_key_invalid", false, nil)
	}
	return digest("COH-EVIDENCE-LIFECYCLE-IDEMPOTENCY-V1\x00", []byte(value)), nil
}

func ArtifactSetBindingDigest(values []ManifestArtifact) (string, error) {
	if !validManifestArtifacts(values, "restricted", 4096) {
		return "", newError(InvalidInput, "artifact_set_invalid", false, nil)
	}
	canonical, err := canonicalValue(values)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-ARTIFACT-SET-V1\x00", canonical), nil
}

func ComponentSetBindingDigest(values []Component) (string, error) {
	if !validComponents(values) {
		return "", newError(InvalidInput, "component_set_invalid", false, nil)
	}
	canonical, err := canonicalValue(values)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-COMPONENT-SET-V1\x00", canonical), nil
}

func LineageBindingDigest(values []ManifestArtifact) (string, error) {
	if !validManifestArtifacts(values, "restricted", 4096) {
		return "", newError(InvalidInput, "lineage_invalid", false, nil)
	}
	type lineageEntry struct {
		Ordinal               uint16
		ArtifactDigest        string
		ManifestDigest        string
		ParentArtifactDigests []string
		ParentManifestDigests []string
	}
	entries := make([]lineageEntry, len(values))
	for index, value := range values {
		entries[index] = lineageEntry{value.Ordinal, value.Reference.Artifact.Digest,
			value.Reference.Manifest.Digest, value.ParentArtifactDigests, value.ParentManifestDigests}
	}
	canonical, err := canonicalValue(entries)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LINEAGE-V1\x00", canonical), nil
}

func CustodyReceiptSetBindingDigest(values []CustodyProof) (string, error) {
	if len(values) == 0 || len(values) > 4096 {
		return "", newError(InvalidInput, "custody_proof_set_invalid", false, nil)
	}
	for index, value := range values {
		if !allDigests(value.ReceiptDigest, value.RecordDigest, value.AuditDigest) || !validHead(value.Head) ||
			index > 0 && value.Head.Sequence != values[index-1].Head.Sequence+1 {
			return "", newError(InvalidInput, "custody_proof_set_invalid", false, nil)
		}
	}
	canonical, err := canonicalValue(values)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-CUSTODY-RECEIPT-SET-V1\x00", canonical), nil
}

func ManifestBindingDigest(value ExportManifest) (string, error) {
	copyValue := value
	copyValue.ManifestDigest = ""
	if err := validateManifestShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-EXPORT-MANIFEST-V1\x00", canonical), nil
}

func SignatureBindingDigest(value DetachedSignature) (string, error) {
	if err := ValidateDetachedSignature(value); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(value)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-DETACHED-SIGNATURE-V1\x00", canonical), nil
}

func HeaderBindingDigest(value PackageHeader) (string, error) {
	copyValue := value
	copyValue.HeaderDigest = ""
	if err := validateHeaderShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-PACKAGE-HEADER-V1\x00", canonical), nil
}

func VerificationBindingDigest(value ImportVerification) (string, error) {
	copyValue := value
	copyValue.ReportDigest = ""
	if err := validateVerificationShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-IMPORT-VERIFICATION-V1\x00", canonical), nil
}

func AuthorizationBindingDigest(value AuthorizationRequest) (string, error) {
	copyValue := value
	copyValue.AuthorizationDigest = ""
	if err := validateAuthorizationShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-AUTHORIZATION-V1\x00", canonical), nil
}

func DecisionBindingDigest(value Decision) (string, error) {
	copyValue := value
	copyValue.DecisionDigest = ""
	if err := validateDecisionShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-DECISION-V1\x00", canonical), nil
}

func ProgressBindingDigest(value Progress) (string, error) {
	copyValue := value
	copyValue.ProgressDigest = ""
	if err := validateProgressShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-PROGRESS-V1\x00", canonical), nil
}

func DispositionBindingDigest(value DispositionAttestation) (string, error) {
	copyValue := value
	copyValue.AttestationDigest = ""
	if err := validateDispositionShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-DISPOSITION-ATTESTATION-V1\x00", canonical), nil
}

func RecordProvenanceDigest(value Record) (string, error) {
	copyValue := value
	copyValue.ProvenanceDigest, copyValue.RecordDigest, copyValue.AuditEventDigest = "", "", ""
	if err := validateRecordShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-PROVENANCE-V1\x00", canonical), nil
}

func RecordBindingDigest(value Record) (string, error) {
	copyValue := value
	copyValue.RecordDigest = ""
	if err := validateRecordShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-RECORD-V1\x00", canonical), nil
}

func RecordPrecommitDigest(value Record) (string, error) {
	copyValue := value
	copyValue.AuditEventDigest, copyValue.RecordDigest = "", ""
	if err := validateRecordShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-RECORD-PRECOMMIT-V1\x00", canonical), nil
}

func ReceiptBindingDigest(value Receipt) (string, error) {
	copyValue := value
	copyValue.ReceiptDigest = ""
	if err := validateReceiptShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(copyValue)
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-LIFECYCLE-RECEIPT-V1\x00", canonical), nil
}

func canonicalValue(value any) ([]byte, error) {
	wire, err := toWireValue(reflect.ValueOf(value))
	if err != nil {
		return nil, newError(InvalidInput, "canonical_value_invalid", false, err)
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, newError(InvalidInput, "canonical_value_invalid", false, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(InvalidInput, "canonical_value_invalid", false, err)
	}
	return canonical, nil
}

func toWireValue(value reflect.Value) (any, error) {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil, nil
		}
		return toWireValue(value.Elem())
	}
	if value.Type() == reflect.TypeOf(time.Time{}) {
		return value.Interface().(time.Time).Format("2006-01-02T15:04:05.000000000Z"), nil
	}
	switch value.Kind() {
	case reflect.Struct:
		result := make(map[string]any, value.NumField())
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			converted, err := toWireValue(value.Field(index))
			if err != nil {
				return nil, err
			}
			result[snakeName(field.Name)] = converted
		}
		return result, nil
	case reflect.Slice, reflect.Array:
		result := make([]any, value.Len())
		for index := range result {
			converted, err := toWireValue(value.Index(index))
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	case reflect.String:
		return value.String(), nil
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Uint(), nil
	default:
		return nil, &json.UnsupportedTypeError{Type: value.Type()}
	}
}

func snakeName(value string) string {
	runes := []rune(value)
	var output strings.Builder
	for index, current := range runes {
		if unicode.IsUpper(current) && index > 0 && (unicode.IsLower(runes[index-1]) ||
			index+1 < len(runes) && unicode.IsLower(runes[index+1])) {
			output.WriteByte('_')
		}
		output.WriteRune(unicode.ToLower(current))
	}
	return output.String()
}
