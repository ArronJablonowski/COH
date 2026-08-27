package mappingregistry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
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
	semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)
	pathPattern   = regexp.MustCompile(`^(original|ocsf|ecs)(\.[A-Za-z0-9_-]+)+$`)
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func validateSignedMapping(ctx context.Context, signed SignedMapping) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if signed.SchemaVersion != SignedSchemaVersion || signed.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(signed.PublisherID) || signed.PublisherID != signed.Manifest.IssuerID ||
		!tokenPattern.MatchString(signed.PublisherKeyID) || signed.PublisherKeyRevision == 0 || signed.PublisherKeyRevision > math.MaxInt64 ||
		signed.SignatureAlgorithm != "ed25519" {
		return newError(InvalidInput, SignatureInvalid, nil)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(decoded) != 64 || len(signed.Signature) != 86 || base64.RawURLEncoding.EncodeToString(decoded) != signed.Signature {
		return newError(InvalidInput, SignatureInvalid, err)
	}
	_, digest, err := CanonicalManifest(ctx, signed.Manifest)
	if err != nil {
		return err
	}
	if signed.ManifestDigest != digest {
		return newError(InvalidInput, ManifestDigestMismatch, nil)
	}
	return nil
}

func validateManifest(ctx context.Context, value Manifest) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != ManifestSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.MappingID) || !tokenPattern.MatchString(value.Name) ||
		!semverPattern.MatchString(value.Version) || len(value.Version) > 128 || value.Revision == 0 || value.Revision > math.MaxInt64 ||
		value.Revision == 1 && value.PredecessorDigest != nil || value.Revision > 1 && !validOptionalDigest(value.PredecessorDigest) ||
		!validSource(value.Source) || !validCompatibility(value.Compatibility) ||
		len(value.Rules) == 0 || len(value.Rules) > 512 || value.IgnoredFields == nil || len(value.IgnoredFields) > 512 ||
		!slices.Contains([]string{"deny", "record_partial"}, value.UnmappedPolicy) || !validLimits(value.Limits) ||
		int(value.Limits.MaxRules) < len(value.Rules) || !uuidPattern.MatchString(value.IssuerID) ||
		!digestPattern.MatchString(value.ReviewDigest) || !validRevocation(value.Revocation) {
		return newError(InvalidInput, ManifestInvalid, nil)
	}
	created, createdOK := parseTimestamp(value.CreatedAt)
	notBefore, beforeOK := parseTimestamp(value.NotBefore)
	notAfter, afterOK := parseTimestamp(value.NotAfter)
	if !createdOK || !beforeOK || !afterOK || created.After(notBefore) || !notAfter.After(notBefore) {
		return newError(InvalidInput, ManifestInvalid, nil)
	}
	if err := validateRules(ctx, value.Rules); err != nil {
		return err
	}
	return validateIgnored(value.IgnoredFields, value.Rules)
}

func validateRules(ctx context.Context, rules []Rule) error {
	ids := make(map[string]struct{}, len(rules))
	outputs := make([]string, 0, len(rules))
	for index, rule := range rules {
		if index%64 == 0 {
			if err := checkContext(ctx); err != nil {
				return err
			}
		}
		if rule.Sequence != uint16(index+1) || !tokenPattern.MatchString(rule.RuleID) {
			return newError(InvalidInput, RuleInvalid, nil)
		}
		if _, exists := ids[rule.RuleID]; exists {
			return newError(ConflictError, RuleInvalid, nil)
		}
		ids[rule.RuleID] = struct{}{}
		if !slices.Contains([]string{"ocsf", "ecs"}, rule.OutputNamespace) || !validPath(rule.OutputPath, rule.OutputNamespace) ||
			!validValueType(rule.InputType) || !validValueType(rule.OutputType) || !validRule(rule) || !validEntityHint(rule.EntityHint, rule.OutputType) {
			return newError(InvalidInput, RuleInvalid, nil)
		}
		for _, output := range outputs {
			if pathCollision(output, rule.OutputPath) {
				return newError(ConflictError, OutputCollision, nil)
			}
		}
		outputs = append(outputs, rule.OutputPath)
	}
	return nil
}

func validRule(rule Rule) bool {
	if !slices.Contains([]Operation{Copy, Constant, Enum, ToInteger, ToString, TimestampReference}, rule.Operation) ||
		!slices.Contains([]string{"reversible", "not_reversible"}, rule.Reversibility) ||
		!slices.Contains([]string{"lossless", "lossy"}, rule.LossState) || !validLossReason(rule.LossReason) ||
		!validReverseLoss(rule) {
		return false
	}
	nullConstant := bytes.Equal(rule.ConstantValue, []byte(`null`))
	switch rule.Operation {
	case Constant:
		return rule.InputPath == nil && validScalar(rule.ConstantValue, rule.OutputType) && rule.EnumTable != nil && len(rule.EnumTable) == 0 &&
			rule.IntegerRange == nil && !rule.Required && rule.Reversibility == "not_reversible" && rule.LossReason == "constant" && rule.EntityHint == nil
	case Enum:
		return validInput(rule.InputPath) && nullConstant && len(rule.EnumTable) > 0 && len(rule.EnumTable) <= 256 &&
			rule.IntegerRange == nil && validEnumTable(rule.EnumTable, rule.InputType, rule.OutputType, rule.Reversibility == "reversible")
	case Copy:
		return validInput(rule.InputPath) && nullConstant && rule.EnumTable != nil && len(rule.EnumTable) == 0 && rule.IntegerRange == nil && rule.InputType == rule.OutputType && rule.Reversibility == "reversible"
	case ToInteger:
		return validInput(rule.InputPath) && nullConstant && rule.EnumTable != nil && len(rule.EnumTable) == 0 && rule.IntegerRange != nil && rule.IntegerRange.Minimum <= rule.IntegerRange.Maximum &&
			rule.InputType == String && rule.OutputType == Integer && slices.Contains([]string{"none", "lexical_normalization", "type_narrowing"}, rule.LossReason)
	case ToString:
		return validInput(rule.InputPath) && nullConstant && rule.EnumTable != nil && len(rule.EnumTable) == 0 && rule.IntegerRange == nil &&
			slices.Contains([]ValueType{Integer, Boolean}, rule.InputType) && rule.OutputType == String
	case TimestampReference:
		return validInput(rule.InputPath) && nullConstant && rule.EnumTable != nil && len(rule.EnumTable) == 0 && rule.IntegerRange == nil &&
			rule.InputType == TimestampText && rule.OutputType == TimestampText && rule.Reversibility == "reversible"
	default:
		return false
	}
}

func validReverseLoss(rule Rule) bool {
	if rule.Operation == Constant {
		return rule.Reversibility == "not_reversible" && rule.LossState == "lossless" && rule.LossReason == "constant"
	}
	if rule.Reversibility == "reversible" {
		return rule.LossState == "lossless" && rule.LossReason == "none"
	}
	if rule.LossState == "lossless" {
		return rule.LossReason == "none"
	}
	return rule.LossReason != "none"
}

func validEnumTable(entries []EnumEntry, inputType, outputType ValueType, reversible bool) bool {
	sources, targets := make(map[string]struct{}, len(entries)), make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if !validScalar(entry.Source, inputType) || !validScalar(entry.Target, outputType) {
			return false
		}
		source, sourceDigest, err := canonicalValue(json.RawMessage(entry.Source))
		if err != nil {
			return false
		}
		_, targetDigest, err := canonicalValue(json.RawMessage(entry.Target))
		if err != nil {
			return false
		}
		if _, exists := sources[string(source)+sourceDigest]; exists {
			return false
		}
		sources[string(source)+sourceDigest] = struct{}{}
		if reversible {
			if _, exists := targets[targetDigest]; exists {
				return false
			}
			targets[targetDigest] = struct{}{}
		}
	}
	return true
}

func validScalar(raw json.RawMessage, kind ValueType) bool {
	canonical, err := domaincontract.Canonicalize(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return false
	}
	switch kind {
	case String, TimestampText:
		_, ok := value.(string)
		return ok
	case Integer:
		number, ok := value.(json.Number)
		return ok && !strings.ContainsAny(number.String(), ".eE+")
	case Boolean:
		_, ok := value.(bool)
		return ok
	case Null:
		return value == nil
	default:
		return false
	}
}

func validateIgnored(values []IgnoredField, rules []Rule) error {
	previous := ""
	for _, value := range values {
		if !validPath(value.Path, "original") || value.Path <= previous || !slices.Contains([]string{"duplicate_vendor_metadata", "nonsemantic_display", "unsupported_vendor_extension", "privacy_minimized", "reserved"}, value.Reason) {
			return newError(InvalidInput, RuleInvalid, nil)
		}
		for _, rule := range rules {
			if rule.InputPath != nil && *rule.InputPath == value.Path {
				return newError(ConflictError, RuleInvalid, nil)
			}
		}
		previous = value.Path
	}
	return nil
}

func validSource(value SourceMatcher) bool {
	return slices.Contains([]string{"upload", "connector", "query", "tool", "model", "derived", "import"}, value.SourceKind) &&
		tokenPattern.MatchString(value.Product) && value.ProductDigest == digestBytes([]byte(value.Product)) && tokenPattern.MatchString(value.SourceSchema) &&
		len(value.SourceSchemaVersion) > 0 && len(value.SourceSchemaVersion) <= 256 && utf8.ValidString(value.SourceSchemaVersion) && digestPattern.MatchString(value.SourceSchemaDigest) &&
		tokenPattern.MatchString(value.CollectionMethod) && len(value.CollectionMethodVersion) > 0 && len(value.CollectionMethodVersion) <= 256 && utf8.ValidString(value.CollectionMethodVersion) &&
		(value.SourceIdentityDigest == nil || digestPattern.MatchString(*value.SourceIdentityDigest))
}

func validCompatibility(value Compatibility) bool {
	return value == (Compatibility{TargetManifestDigest, "coh.normalized-event-envelope/v1", OCSFVersion, OCSFCommit, ECSVersion, ECSCommit})
}

func validLimits(value Limits) bool {
	return value.MaxRules > 0 && value.MaxRules <= 512 && value.MaxInputLeaves > 0 && value.MaxInputLeaves <= 4096 && value.MaxOutputLeaves > 0 && value.MaxOutputLeaves <= 4096 &&
		value.MaxValueBytes > 0 && value.MaxValueBytes <= 65536 && value.MaxDepth > 0 && value.MaxDepth <= 64
}

func validRevocation(value RevocationBinding) bool {
	return uuidPattern.MatchString(value.ListID) && digestPattern.MatchString(value.ListDigest) && value.MinimumRevision > 0 && value.MinimumRevision <= math.MaxInt64
}
func validOptionalDigest(value *string) bool {
	return value != nil && digestPattern.MatchString(*value)
}
func validInput(value *string) bool { return value != nil && validPath(*value, "original") }
func validValueType(value ValueType) bool {
	return slices.Contains([]ValueType{String, Integer, Boolean, Null, TimestampText}, value)
}
func validLossReason(value string) bool {
	return slices.Contains([]string{"none", "constant", "lexical_normalization", "type_narrowing", "enum_many_to_one", "source_precision", "declared_vendor_loss"}, value)
}

func validEntityHint(value *EntityHint, outputType ValueType) bool {
	if value == nil {
		return true
	}
	if value.ConfidenceCeilingMillionths > 1_000_000 {
		return false
	}
	switch value.Role {
	case "host.name":
		return outputType == String && value.IdentifierType == "hostname" && slices.Contains([]string{"identity", "lowercase_ascii"}, value.Normalization)
	case "user.name":
		return outputType == String && value.IdentifierType == "username" && slices.Contains([]string{"identity", "lowercase_ascii"}, value.Normalization)
	case "network.ip":
		return outputType == String && slices.Contains([]string{"ipv4", "ipv6"}, value.IdentifierType) && value.Normalization == "ip_canonical"
	case "process.id":
		return slices.Contains([]ValueType{String, Integer}, outputType) && value.IdentifierType == "process_id" && value.Normalization == "decimal_canonical"
	case "file.hash":
		return outputType == String && value.IdentifierType == "sha256" && value.Normalization == "sha256_lowercase"
	case "cloud.resource_id":
		return outputType == String && value.IdentifierType == "cloud_resource_id" && value.Normalization == "identity"
	default:
		return false
	}
}

func validPath(value, root string) bool {
	if len(value) > 1024 || !pathPattern.MatchString(value) {
		return false
	}
	parts := strings.Split(value, ".")
	if parts[0] != root || len(parts) < 2 || len(parts) > 17 {
		return false
	}
	for _, part := range parts[1:] {
		if len(part) == 0 || len(part) > 128 {
			return false
		}
	}
	return true
}

func pathCollision(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+".") || strings.HasPrefix(right, left+".")
}
func parseTimestamp(value string) (time.Time, bool) {
	parsed, err := time.Parse(timestampLayout, value)
	return parsed, err == nil && parsed.Format(timestampLayout) == value
}
