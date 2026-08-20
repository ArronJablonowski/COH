package filesize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	requiredThresholds = Thresholds{WarningLimit, HardLimit, ScriptLimit, NormalMinimum, NormalMaximum}
	issuePattern       = regexp.MustCompile(`^CYB-[1-9][0-9]*$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	validCategories    = map[string]bool{
		"generated": true, "vendor": true, "schema": true,
		"migration_data": true, "large_fixture": true, "script": true,
	}
)

func DecodePolicy(data []byte) (Policy, error) {
	if len(data) == 0 || len(data) > MaximumPolicySize || !utf8.Valid(data) {
		return Policy{}, contractError(CodeInvalidInput, "policy", "policy size is invalid", nil)
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return Policy{}, contractError(CodeInvalidInput, "policy", "duplicate or malformed JSON", err)
	}
	if err := validatePolicyJSONShape(data); err != nil {
		return Policy{}, contractError(CodeInvalidInput, "policy", "policy keys must match the v1 schema exactly", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, contractError(CodeInvalidInput, "policy", "invalid policy JSON", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Policy{}, contractError(CodeInvalidInput, "policy", "trailing JSON is forbidden", err)
	}
	if err := ValidatePolicy(policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func validatePolicyJSONShape(data []byte) error {
	root, err := exactObject(data, []string{"exceptions", "policy_version", "schema_version", "thresholds"}, nil)
	if err != nil {
		return err
	}
	if _, err := exactObject(root["thresholds"], []string{
		"hard_physical_lines", "normal_maximum_lines", "normal_minimum_lines",
		"script_physical_lines", "warning_physical_lines",
	}, nil); err != nil {
		return err
	}
	var exceptions []json.RawMessage
	if trimmed := bytes.TrimSpace(root["exceptions"]); len(trimmed) == 0 || trimmed[0] != '[' {
		return errors.New("exceptions must be an array")
	}
	if err := json.Unmarshal(root["exceptions"], &exceptions); err != nil {
		return err
	}
	required := []string{
		"approved_max_physical_lines", "category", "content_sha256", "expires_on",
		"justification", "owner", "path", "tracking_issue",
	}
	for _, raw := range exceptions {
		object, err := exactObject(raw, required, []string{"generator"})
		if err != nil {
			return err
		}
		if generator, present := object["generator"]; present {
			trimmed := bytes.TrimSpace(generator)
			if len(trimmed) == 0 || trimmed[0] != '"' {
				return errors.New("generator must be a JSON string")
			}
		}
	}
	return nil
}

func exactObject(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, errors.New("value must be an object")
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = true
		if _, present := object[name]; !present {
			return nil, errors.New("required object name is missing")
		}
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name := range object {
		if !allowed[name] {
			return nil, errors.New("unknown or case-variant object name")
		}
	}
	return object, nil
}

func ValidatePolicy(policy Policy) error {
	if policy.SchemaVersion != PolicySchema || policy.PolicyVersion != PolicyVersion {
		return contractError(CodeInvalidInput, "version", "unsupported file-size policy version", nil)
	}
	if policy.Thresholds != requiredThresholds {
		return contractError(CodeDenied, "thresholds", "file-size thresholds are executable constants", nil)
	}
	if policy.Exceptions == nil {
		return contractError(CodeInvalidInput, "exceptions", "exceptions must be a non-null array", nil)
	}
	if len(policy.Exceptions) > MaximumExceptions {
		return contractError(CodeInvalidInput, "exceptions", "too many exceptions", nil)
	}
	seen := make(map[string]struct{}, len(policy.Exceptions))
	seenFolded := make(map[string]struct{}, len(policy.Exceptions))
	previous := ""
	for index, exception := range policy.Exceptions {
		field := "exceptions[" + decimal(index) + "]"
		if err := validateException(exception, field); err != nil {
			return err
		}
		if index > 0 && previous >= exception.Path {
			return contractError(CodeInvalidInput, "exceptions", "exceptions must be path-sorted and unique", nil)
		}
		folded := strings.ToLower(exception.Path)
		if _, exists := seen[exception.Path]; exists {
			return contractError(CodeInvalidInput, field+".path", "duplicate exception path", nil)
		}
		if _, exists := seenFolded[folded]; exists {
			return contractError(CodeInvalidInput, field+".path", "case-colliding exception path", nil)
		}
		seen[exception.Path] = struct{}{}
		seenFolded[folded] = struct{}{}
		previous = exception.Path
	}
	return nil
}

func validateException(exception Exception, field string) error {
	if !safePolicyPath(exception.Path) {
		return contractError(CodeInvalidInput, field+".path", "path must be an exact safe repository path", nil)
	}
	if !validCategories[exception.Category] {
		return contractError(CodeInvalidInput, field+".category", "unsupported exception category", nil)
	}
	if !normalizedBounded(exception.Owner, 2, 128) {
		return contractError(CodeInvalidInput, field+".owner", "owner must be normalized and bounded", nil)
	}
	if !normalizedBounded(exception.Justification, 20, 512) {
		return contractError(CodeInvalidInput, field+".justification", "justification must be normalized and 20-512 bytes", nil)
	}
	if _, err := parseDate(exception.ExpiresOn); err != nil {
		return contractError(CodeInvalidInput, field+".expires_on", "date must be strict UTC YYYY-MM-DD", err)
	}
	if !issuePattern.MatchString(exception.TrackingIssue) || !digestPattern.MatchString(exception.ContentSHA256) {
		return contractError(CodeInvalidInput, field, "tracking issue or content digest is invalid", nil)
	}
	minimum := HardLimit
	if exception.Category == "script" {
		minimum = ScriptLimit
	}
	maximum := MaximumApproved
	if exception.Category == "script" {
		maximum = HardLimit
	}
	if exception.ApprovedMaxPhysicalLines <= minimum || exception.ApprovedMaxPhysicalLines > maximum {
		return contractError(CodeInvalidInput, field+".approved_max_physical_lines", "approved maximum is outside the bounded exception range", nil)
	}
	requiresGenerator := exception.Category != "script"
	if requiresGenerator && !normalizedBounded(exception.Generator, 1, 128) {
		return contractError(CodeInvalidInput, field+".generator", "category requires a bounded generator identity", nil)
	}
	if !requiresGenerator && exception.Generator != "" && !normalizedBounded(exception.Generator, 1, 128) {
		return contractError(CodeInvalidInput, field+".generator", "generator must be normalized when present", nil)
	}
	return nil
}

func CanonicalPolicy(policy Policy) ([]byte, error) {
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	return json.Marshal(policy)
}

func PolicyDigest(policy Policy) (string, error) {
	data, err := CanonicalPolicy(policy)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

func ExceptionsDigest(policy Policy) (string, error) {
	if err := ValidatePolicy(policy); err != nil {
		return "", err
	}
	data, err := json.Marshal(policy.Exceptions)
	if err != nil {
		return "", contractError(CodeToolFailure, "exceptions", "cannot canonicalize exceptions", err)
	}
	return digestBytes(data), nil
}

func safePolicyPath(value string) bool {
	if value == "" || len(value) > MaximumPathSize || !utf8.ValidString(value) || strings.HasPrefix(value, "/") ||
		strings.ContainsAny(value, "\\\r\n\x00*?[]") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func normalizedBounded(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum &&
		value == strings.TrimSpace(value) && value == strings.Join(strings.Fields(value), " ")
}

func parseDate(value string) (time.Time, error) {
	if len(value) != len("2006-01-02") {
		return time.Time{}, errors.New("wrong date length")
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil || parsed.Format("2006-01-02") != value {
		return time.Time{}, errors.New("invalid date")
	}
	return parsed.UTC(), nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func decimal(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	result := make([]byte, 0, 8)
	for value > 0 {
		result = append(result, digits[value%10])
		value /= 10
	}
	slices.Reverse(result)
	return string(result)
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("object name is not a string")
				}
				if _, duplicate := seen[name]; duplicate {
					return errors.New("duplicate object name")
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected closing delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}
