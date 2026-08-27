package investigationprojection

import (
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func validScope(value Scope) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validKind(value Kind) bool {
	return slices.Contains([]Kind{Correlation, Hypothesis, Timeline}, value)
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(timestampLayout, value)
	return err == nil && parsed.Format(timestampLayout) == value && strings.HasSuffix(value, "Z")
}

func validDigestSet(values []string) bool {
	if values == nil || len(values) > MaximumFacts {
		return false
	}
	for index, value := range values {
		if !digestPattern.MatchString(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validTokenSet(values []string) bool {
	if values == nil || len(values) > MaximumOutputs {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validEntityRefs(values []EntityRef) bool {
	if values == nil || len(values) > MaximumOutputs {
		return false
	}
	for index, value := range values {
		if !uuidPattern.MatchString(value.EntityID) || value.Revision == 0 || value.Revision > math.MaxInt64 ||
			!digestPattern.MatchString(value.RecordDigest) || index > 0 && compareEntityRef(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}

func compareEntityRef(left, right EntityRef) int {
	if left.EntityID != right.EntityID {
		return strings.Compare(left.EntityID, right.EntityID)
	}
	if left.Revision < right.Revision {
		return -1
	}
	if left.Revision > right.Revision {
		return 1
	}
	return strings.Compare(left.RecordDigest, right.RecordDigest)
}

func validTimeRefs(values []TimeRef) bool {
	if values == nil || len(values) > MaximumOutputs {
		return false
	}
	precisions := []string{"nanosecond", "microsecond", "millisecond", "second", "minute", "hour", "day", "unknown"}
	for index, value := range values {
		if !digestPattern.MatchString(value.TimeRecordDigest) || value.ComparisonDigest != nil &&
			!digestPattern.MatchString(*value.ComparisonDigest) || !slices.Contains(precisions, value.Precision) ||
			!digestPattern.MatchString(value.UncertaintyDigest) || index > 0 && compareTimeRef(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}

func compareTimeRef(left, right TimeRef) int {
	if left.TimeRecordDigest != right.TimeRecordDigest {
		return strings.Compare(left.TimeRecordDigest, right.TimeRecordDigest)
	}
	leftComparison, rightComparison := "", ""
	if left.ComparisonDigest != nil {
		leftComparison = *left.ComparisonDigest
	}
	if right.ComparisonDigest != nil {
		rightComparison = *right.ComparisonDigest
	}
	return strings.Compare(leftComparison, rightComparison)
}

func validUnknowns(values []Unknown) bool {
	if values == nil || len(values) > MaximumOutputs {
		return false
	}
	allowed := []string{"missing_telemetry", "missing_timezone", "low_precision", "clock_skew", "source_conflict",
		"identity_ambiguous", "query_incomplete", "unresolved_claim"}
	for index, value := range values {
		if !slices.Contains(allowed, value.Code) || !digestPattern.MatchString(value.BasisDigest) ||
			index > 0 && compareUnknown(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}

func compareUnknown(left, right Unknown) int {
	if left.Code != right.Code {
		return strings.Compare(left.Code, right.Code)
	}
	return strings.Compare(left.BasisDigest, right.BasisDigest)
}

func validCompleteness(value Completeness) bool {
	if !slices.Contains([]string{"complete", "partial", "unknown"}, value.Status) ||
		!validDigestSet(value.QueriedSourceDigests) || !validDigestSet(value.CompletedSourceDigests) ||
		!validDigestSet(value.GapDigests) || !validDigestSet(value.NegativeEvidenceDigests) ||
		!validDigestSet(value.ConflictDigests) {
		return false
	}
	for _, digest := range value.CompletedSourceDigests {
		if !slices.Contains(value.QueriedSourceDigests, digest) {
			return false
		}
	}
	return value.Status != "complete" || slices.Equal(value.QueriedSourceDigests, value.CompletedSourceDigests) &&
		len(value.GapDigests) == 0 && len(value.ConflictDigests) == 0
}

func validConfidence(value Confidence) bool {
	if !slices.Contains([]string{"coh.entity-confidence", "coh.projection-confidence"}, value.Method) ||
		value.MethodVersion != ReducerVersion || !digestPattern.MatchString(value.BasisDigest) || value.ValueMillionths > 1_000_000 {
		return false
	}
	return value.Label == confidenceLabel(value.ValueMillionths)
}

func confidenceLabel(value uint32) string {
	switch {
	case value < 250_000:
		return "very_low"
	case value < 500_000:
		return "low"
	case value < 750_000:
		return "medium"
	case value < 900_000:
		return "high"
	default:
		return "very_high"
	}
}

func validStateVersion(value StateVersion) bool {
	return value.ReducerVersion == ReducerVersion && value.ProjectionSchemaVersion == ProjectionSchemaVersion &&
		value.NormalizedEventSchemaVersion == "coh.normalized-event-envelope/v1" && value.MappingContractVersion == ContractVersion &&
		digestPattern.MatchString(value.MappingManifestDigest) && value.MappingRevision > 0 && value.MappingRevision <= math.MaxInt64 &&
		value.EntityContractVersion == ContractVersion && digestPattern.MatchString(value.EntityHeadDigest) &&
		value.TimeContractVersion == ContractVersion && value.TimeMethodVersion == ReducerVersion &&
		digestPattern.MatchString(value.AuthoritativeStateDigest)
}

func validWatermark(value Watermark) bool {
	if !validTimestamp(value.CommittedAt) || !digestPattern.MatchString(value.AuthoritativeStateDigest) {
		return false
	}
	if value.Sequence == 0 {
		return value.HeadFactDigest == nil
	}
	return value.Sequence <= math.MaxInt64 && value.HeadFactDigest != nil && digestPattern.MatchString(*value.HeadFactDigest)
}
