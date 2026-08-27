package normalizedevent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	mediaPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`)
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func validate(ctx context.Context, envelope Envelope) error {
	if envelope.SchemaVersion != EnvelopeSchemaVersion || envelope.ContractVersion != ContractVersion {
		return invalid("unsupported_contract")
	}
	if !uuidPattern.MatchString(envelope.EnvelopeID) || !validCase(envelope.Case) {
		return invalid("envelope_scope")
	}
	if !validTimestamp(envelope.CollectedAt) || !validClassification(envelope.Classification) {
		return invalid("envelope_metadata")
	}
	if err := validateSource(envelope.Source); err != nil {
		return err
	}
	if envelope.Compatibility != (Compatibility{TargetManifestDigest: TargetManifestDigest,
		OCSFVersion: OCSFVersion, OCSFCommit: OCSFCommit, ECSVersion: ECSVersion, ECSCommit: ECSCommit}) {
		return invalid("compatibility_target")
	}
	if err := validateOriginal(ctx, envelope.Original); err != nil {
		return err
	}
	if err := validateOCSF(ctx, envelope.OCSF); err != nil {
		return err
	}
	if err := validateECS(ctx, envelope.ECS); err != nil {
		return err
	}
	if err := validateLineage(envelope); err != nil {
		return err
	}
	if err := validateNormalization(envelope); err != nil {
		return err
	}
	if err := validateDataset(envelope); err != nil {
		return err
	}
	return checkContext(ctx)
}

func validateSource(source Source) error {
	if !oneOf(source.Kind, "upload", "connector", "query", "tool", "model", "derived", "import") ||
		len(source.Identity) == 0 || len(source.Identity) > 1024 || !utf8.ValidString(source.Identity) ||
		source.IdentityDigest != digestBytes([]byte(source.Identity)) || !tokenPattern.MatchString(source.CollectionMethod) ||
		len(source.CollectionMethodVersion) == 0 || len(source.CollectionMethodVersion) > 256 {
		return invalid("source_binding")
	}
	return nil
}

func validateOriginal(ctx context.Context, original Original) error {
	if !oneOf(original.Format, "json", "ndjson", "cef", "leef", "syslog", "xml", "csv", "text", "binary") {
		return invalid("original_format")
	}
	canonical, object, err := validateRawObject(ctx, original.Fields, 1024)
	if err != nil || len(object) == 0 || original.FieldsDigest != digestBytes(canonical) {
		return invalidCause("original_fields", err)
	}
	return nil
}

func validateOCSF(ctx context.Context, ocsf OCSF) error {
	if ocsf.Version != OCSFVersion || ocsf.SchemaCommit != OCSFCommit {
		return invalid("ocsf_target")
	}
	canonical, event, err := validateRawObject(ctx, ocsf.Event, 1024)
	if err != nil || len(event) < 7 || ocsf.EventDigest != digestBytes(canonical) {
		return invalidCause("ocsf_event", err)
	}
	activity, activityOK := integer(event["activity_id"])
	category, categoryOK := integer(event["category_uid"])
	class, classOK := integer(event["class_uid"])
	severity, severityOK := integer(event["severity_id"])
	eventTime, timeOK := integer(event["time"])
	typeUID, typeOK := integer(event["type_uid"])
	if !activityOK || activity < 0 || activity > 99 || !categoryOK || category < 0 || category > 99 ||
		!classOK || class <= 0 || class > 999999 || !severityOK || severity < 0 || severity > 99 ||
		!timeOK || eventTime < 0 || !typeOK || typeUID != class*100+activity || category != class/1000 {
		return invalid("ocsf_base_fields")
	}
	metadata, ok := event["metadata"].(map[string]any)
	product, productOK := metadata["product"].(map[string]any)
	version, versionOK := metadata["version"].(string)
	if !ok || !productOK || len(product) == 0 || len(product) > 64 || !versionOK || version != OCSFVersion || len(metadata) > 64 {
		return invalid("ocsf_metadata")
	}
	return nil
}

func validateECS(ctx context.Context, ecs *ECS) error {
	if ecs == nil {
		return nil
	}
	if ecs.Version != ECSVersion || ecs.SchemaCommit != ECSCommit {
		return invalid("ecs_target")
	}
	canonical, object, err := validateRawObject(ctx, ecs.Fields, 1024)
	if err != nil || len(object) == 0 || ecs.FieldsDigest != digestBytes(canonical) {
		return invalidCause("ecs_fields", err)
	}
	return nil
}

func validateLineage(envelope Envelope) error {
	lineage := envelope.Lineage
	if !validArtifact(lineage.RawArtifact) || !digestPattern.MatchString(lineage.RawManifestDigest) ||
		!digestPattern.MatchString(lineage.IngestReceiptDigest) || !digestPattern.MatchString(lineage.SourceProvenanceDigest) ||
		!validDigestSet(lineage.ParentEnvelopeDigests, 128) {
		return invalid("lineage_binding")
	}
	if classificationRank(envelope.Classification) < classificationRank(lineage.RawArtifact.Classification) {
		return invalid("classification_downgrade")
	}
	return nil
}

func validateNormalization(envelope Envelope) error {
	normalization := envelope.Normalization
	if !digestPattern.MatchString(normalization.MappingSetDigest) || !validComponent(normalization.Normalizer) ||
		!oneOf(normalization.Coverage, "complete", "partial", "unmapped") ||
		len(normalization.UnmappedVendorPaths) > 1024 || !sortedUniqueStrings(normalization.UnmappedVendorPaths) {
		return invalid("normalization_binding")
	}
	for _, path := range normalization.UnmappedVendorPaths {
		if len(path) == 0 || len(path) > 1024 || !utf8.ValidString(path) {
			return invalid("unmapped_vendor_path")
		}
	}
	if normalization.Coverage == "complete" && len(normalization.UnmappedVendorPaths) != 0 ||
		normalization.Coverage != "complete" && len(normalization.UnmappedVendorPaths) == 0 {
		return invalid("normalization_coverage")
	}
	expected, err := TransformationDigest(envelope)
	if err != nil || normalization.TransformationDigest != expected {
		return invalidCause("transformation_digest", err)
	}
	return nil
}

func validateDataset(envelope Envelope) error {
	if envelope.Dataset == nil {
		return nil
	}
	dataset := envelope.Dataset
	if dataset.Format != "parquet" || !validArtifact(dataset.Artifact) || dataset.Artifact.MediaType != "application/vnd.apache.parquet" ||
		!digestPattern.MatchString(dataset.ManifestDigest) || !digestPattern.MatchString(dataset.SchemaDigest) ||
		len(dataset.PartitionKeys) > 16 || !sortedUniqueStrings(dataset.PartitionKeys) || len(dataset.PartitionValues) > 16 {
		return invalid("dataset_binding")
	}
	if classificationRank(dataset.Artifact.Classification) < classificationRank(envelope.Classification) {
		return invalid("dataset_classification")
	}
	if len(dataset.PartitionKeys) != len(dataset.PartitionValues) {
		return invalid("dataset_partitions")
	}
	for _, key := range dataset.PartitionKeys {
		value, exists := dataset.PartitionValues[key]
		if !exists || !tokenPattern.MatchString(key) || len(value) > 256 || !utf8.ValidString(value) {
			return invalid("dataset_partitions")
		}
	}
	profile := dataset.AccessProfile
	if profile.MaxRows == 0 || profile.MaxRows > 1_000_000 || profile.MaxBytes == 0 || profile.MaxBytes > 1<<30 ||
		profile.MaxPages == 0 || profile.MaxPages > 10_000 || profile.MaxDurationMS == 0 || profile.MaxDurationMS > 3_600_000 {
		return invalid("dataset_limits")
	}
	return nil
}

func TransformationDigest(envelope Envelope) (string, error) {
	var ecsDigest *string
	if envelope.ECS != nil {
		value := envelope.ECS.FieldsDigest
		ecsDigest = &value
	}
	preimage := struct {
		TargetManifestDigest   string    `json:"target_manifest_digest"`
		OriginalFieldsDigest   string    `json:"original_fields_digest"`
		OCSFEventDigest        string    `json:"ocsf_event_digest"`
		ECSFieldsDigest        *string   `json:"ecs_fields_digest"`
		MappingSetDigest       string    `json:"mapping_set_digest"`
		Normalizer             Component `json:"normalizer"`
		RawArtifactDigest      string    `json:"raw_artifact_digest"`
		RawManifestDigest      string    `json:"raw_manifest_digest"`
		IngestReceiptDigest    string    `json:"ingest_receipt_digest"`
		SourceProvenanceDigest string    `json:"source_provenance_digest"`
	}{TargetManifestDigest, envelope.Original.FieldsDigest, envelope.OCSF.EventDigest, ecsDigest,
		envelope.Normalization.MappingSetDigest, envelope.Normalization.Normalizer, envelope.Lineage.RawArtifact.Digest,
		envelope.Lineage.RawManifestDigest, envelope.Lineage.IngestReceiptDigest, envelope.Lineage.SourceProvenanceDigest}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalize(encoded)
	if err != nil {
		return "", err
	}
	return digestBytes(canonical), nil
}

func validateRawObject(ctx context.Context, raw json.RawMessage, maxProperties int) ([]byte, map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaximumInputBytes/2 {
		return nil, nil, fmt.Errorf("raw value size")
	}
	canonical, err := canonicalize(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, nil, fmt.Errorf("non-canonical raw object: %w", err)
	}
	value, err := domaincontract.DecodeUnique(canonical)
	if err != nil {
		return nil, nil, err
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) > maxProperties {
		return nil, nil, fmt.Errorf("object shape")
	}
	visits := 0
	if err := validateDynamic(ctx, value, 0, &visits); err != nil {
		return nil, nil, err
	}
	return canonical, object, nil
}

func validateDynamic(ctx context.Context, value any, depth int, visits *int) error {
	*visits++
	if *visits > 100_000 || depth > 64 {
		return fmt.Errorf("dynamic value bound")
	}
	if *visits%256 == 0 {
		if err := checkContext(ctx); err != nil {
			return err
		}
	}
	switch typed := value.(type) {
	case string:
		if len(typed) > 65_536 || !utf8.ValidString(typed) {
			return fmt.Errorf("dynamic string bound")
		}
	case []any:
		if len(typed) > 4096 {
			return fmt.Errorf("dynamic array bound")
		}
		for _, item := range typed {
			if err := validateDynamic(ctx, item, depth+1, visits); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(typed) > 1024 {
			return fmt.Errorf("dynamic object bound")
		}
		for key, item := range typed {
			if len(key) > 1024 || !utf8.ValidString(key) {
				return fmt.Errorf("dynamic key bound")
			}
			if err := validateDynamic(ctx, item, depth+1, visits); err != nil {
				return err
			}
		}
	}
	return nil
}

func validCase(value Case) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID)
}

func validArtifact(value Artifact) bool {
	return digestPattern.MatchString(value.Digest) && mediaPattern.MatchString(value.MediaType) &&
		validClassification(value.Classification) && value.Length > 0 && value.Length <= 1<<30
}

func validComponent(value Component) bool {
	return tokenPattern.MatchString(value.Name) && len(value.Version) > 0 && len(value.Version) <= 256 && digestPattern.MatchString(value.Digest)
}

func validDigestSet(values []string, maximum int) bool {
	if len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !digestPattern.MatchString(value) || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}

func sortedUniqueStrings(values []string) bool {
	return slices.IsSorted(values) && !hasAdjacentDuplicate(values)
}

func hasAdjacentDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func integer(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(number.String(), ".eE") {
		return 0, false
	}
	result, err := number.Int64()
	return result, err == nil
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(timestampLayout, value)
	return err == nil && parsed.Format(timestampLayout) == value
}

func validClassification(value string) bool {
	return classificationRank(value) >= 0
}

func classificationRank(value string) int {
	switch value {
	case "public":
		return 0
	case "internal":
		return 1
	case "confidential":
		return 2
	case "restricted":
		return 3
	default:
		return -1
	}
}

func oneOf(value string, allowed ...string) bool {
	return slices.Contains(allowed, value)
}

func invalid(reason string) error {
	return newError(InvalidInput, reason, nil)
}

func invalidCause(reason string, cause error) error {
	if code := Code(cause); code == Canceled || code == Timeout {
		return cause
	}
	return newError(InvalidInput, reason, cause)
}
