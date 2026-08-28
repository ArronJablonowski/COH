package modelsurface

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	uuid7Pattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	timePattern   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{9}Z$`)
)

func validUUID7(value string) bool          { return uuid7Pattern.MatchString(value) }
func validDigest(value string) bool         { return digestPattern.MatchString(value) }
func validOptionalDigest(value string) bool { return value == "" || validDigest(value) }
func validToken(value string) bool {
	return tokenPattern.MatchString(value) && strings.TrimSpace(value) == value
}
func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }

func validTimestamp(value string) bool {
	if !timePattern.MatchString(value) {
		return false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05.000000000Z") == value
}

func timestampBefore(first, second string) bool {
	left, leftErr := time.Parse("2006-01-02T15:04:05.000000000Z", first)
	right, rightErr := time.Parse("2006-01-02T15:04:05.000000000Z", second)
	return leftErr == nil && rightErr == nil && left.Before(right)
}

func timestampAtOrAfter(value, lower string) bool {
	current, currentErr := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	minimum, minimumErr := time.Parse("2006-01-02T15:04:05.000000000Z", lower)
	return currentErr == nil && minimumErr == nil && !current.Before(minimum)
}

func validScope(value Scope) bool {
	return validUUID7(value.OrganizationID) && validUUID7(value.TenantID) &&
		validUUID7(value.CaseID) && validUUID7(value.TaskID)
}

func sortedUniqueStrings(values []string, maximum int, validate func(string) bool) bool {
	if values == nil || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validate(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validMediaType(value string, schemaAllowed bool) bool {
	allowed := []string{"application/json", "text/markdown", "text/plain"}
	if schemaAllowed {
		allowed = append(allowed, "application/schema+json")
	}
	return slices.Contains(allowed, value)
}

func validClassification(value string) bool {
	return oneOf(value, "public", "internal", "restricted", "confidential")
}

func validInstructionDisposition(value string) bool {
	return oneOf(value, "trusted_control_instruction", "trusted_system_instruction", "trusted_user_instruction", "untrusted_data_only")
}

func validProjectionRule(value string) bool {
	return oneOf(value, "message", "prompt_section", "tool_schema", "retrieved_context", "compaction_replacement", "policy_notice")
}

func formatUint(value uint64) string { return strconv.FormatUint(value, 10) }
