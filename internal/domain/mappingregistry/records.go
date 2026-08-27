package mappingregistry

import (
	"context"
	"math"
	"slices"
	"time"
)

func CanonicalCommand(ctx context.Context, command Command) ([]byte, string, error) {
	if err := validateCommand(ctx, command); err != nil {
		return nil, "", err
	}
	return canonicalValue(command)
}

func CanonicalOutcome(ctx context.Context, outcome Outcome) ([]byte, string, error) {
	if err := validateOutcome(ctx, outcome); err != nil {
		return nil, "", err
	}
	return canonicalValue(outcome)
}

func CanonicalReceipt(ctx context.Context, receipt Receipt) ([]byte, string, error) {
	if err := validateReceipt(ctx, receipt); err != nil {
		return nil, "", err
	}
	return canonicalValue(receipt)
}

func validateCommand(ctx context.Context, command Command) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if command.SchemaVersion != CommandSchemaVersion || command.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(command.OperationID) || !digestPattern.MatchString(command.IdempotencyKey) ||
		!slices.Contains([]RegistryOperation{Register, Promote, Rollback, Revoke, Apply}, command.Operation) ||
		!validCase(command.Case) || !validSourceBinding(command.SourceBinding) || !validSource(command.Source) ||
		!digestPattern.MatchString(command.MappingDigest) || command.ExpectedRegistryRevision > math.MaxInt64 {
		return newError(InvalidInput, ManifestInvalid, nil)
	}
	requested, requestedOK := parseTimestamp(command.RequestedAt)
	deadline, deadlineOK := parseTimestamp(command.Deadline)
	if !requestedOK || !deadlineOK || !deadline.After(requested) {
		return newError(InvalidInput, ManifestInvalid, nil)
	}
	if command.Operation == Register {
		if command.SignedMapping == nil || command.ExpectedRegistryRevision != 0 || command.MappingDigest != command.SignedMapping.ManifestDigest ||
			!sameSource(command.Source, command.SignedMapping.Manifest.Source) {
			return newError(InvalidInput, ManifestDigestMismatch, nil)
		}
		return validateSignedMapping(ctx, *command.SignedMapping)
	}
	if command.SignedMapping != nil {
		return newError(InvalidInput, ManifestInvalid, nil)
	}
	return nil
}

func validateOutcome(ctx context.Context, outcome Outcome) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if outcome.SchemaVersion != OutcomeSchemaVersion || outcome.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(outcome.OperationID) || !digestPattern.MatchString(outcome.CommandDigest) ||
		!digestPattern.MatchString(outcome.MappingDigest) || outcome.RegistryRevision > math.MaxInt64 ||
		!validStatusReason(outcome.Status, outcome.ReasonCode) || !validTimestampValue(outcome.CreatedAt) ||
		outcome.AppliedRules == nil || outcome.UnmappedPaths == nil || outcome.LossyPaths == nil ||
		outcome.EntityHints == nil || outcome.ReverseResults == nil || len(outcome.AppliedRules) > 512 ||
		len(outcome.UnmappedPaths) > 4096 || len(outcome.LossyPaths) > 4096 {
		return newError(InvalidInput, CoverageInvalid, nil)
	}
	if !uniqueTokens(outcome.AppliedRules) || !sortedPaths(outcome.UnmappedPaths) || !sortedPaths(outcome.LossyPaths) ||
		!validEmittedHints(outcome.EntityHints) || !validReverseResults(outcome.ReverseResults) {
		return newError(InvalidInput, CoverageInvalid, nil)
	}
	if outcome.Status == Applied {
		if outcome.NormalizedEnvelopeDigest == nil || !digestPattern.MatchString(*outcome.NormalizedEnvelopeDigest) ||
			!slices.Contains([]string{"complete", "partial", "unmapped"}, outcome.Coverage) {
			return newError(InvalidInput, CoverageInvalid, nil)
		}
		return nil
	}
	if outcome.NormalizedEnvelopeDigest != nil || outcome.Coverage != "none" || len(outcome.AppliedRules) != 0 ||
		len(outcome.UnmappedPaths) != 0 || len(outcome.LossyPaths) != 0 || len(outcome.EntityHints) != 0 || len(outcome.ReverseResults) != 0 {
		return newError(InvalidInput, CoverageInvalid, nil)
	}
	return nil
}

func validateReceipt(ctx context.Context, receipt Receipt) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if receipt.SchemaVersion != ReceiptSchemaVersion || receipt.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(receipt.OperationID) || !digestPattern.MatchString(receipt.IdempotencyKey) ||
		!digestPattern.MatchString(receipt.CommandDigest) || !digestPattern.MatchString(receipt.OutcomeDigest) ||
		!validStatusReason(receipt.Status, receipt.ReasonCode) || !digestPattern.MatchString(receipt.AuditDigest) ||
		!digestPattern.MatchString(receipt.ProvenanceDigest) || receipt.PreviousProvenanceDigest != nil && !digestPattern.MatchString(*receipt.PreviousProvenanceDigest) ||
		!validTimestampValue(receipt.CreatedAt) || !validTimestampValue(receipt.UpdatedAt) || receipt.UpdatedAt < receipt.CreatedAt {
		return newError(InvalidInput, CoverageInvalid, nil)
	}
	return nil
}

func validCase(value Case) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID)
}

func validSourceBinding(value SourceBinding) bool {
	return uuidPattern.MatchString(value.EnvelopeID) && digestPattern.MatchString(value.EnvelopeDigest) &&
		digestPattern.MatchString(value.ArtifactDigest) && digestPattern.MatchString(value.ManifestDigest) &&
		digestPattern.MatchString(value.IngestReceiptDigest) && digestPattern.MatchString(value.SourceProvenanceDigest) &&
		digestPattern.MatchString(value.OriginalFieldsDigest)
}

func validStatusReason(status Status, reason Reason) bool {
	pairs := map[Status]Reason{Registered: RegisteredReason, Promoted: PromotedReason, RolledBack: RolledBackReason,
		Revoked: RevokedReason, Applied: AppliedReason, Canceled: ContextCanceled, Timeout: ContextDeadline,
		DependencyUnavailable: DependencyUnavailableReason}
	if wanted, exists := pairs[status]; exists {
		return reason == wanted
	}
	if status != Denied {
		return false
	}
	return slices.Contains([]Reason{ManifestInvalid, ManifestDigestMismatch, SignatureInvalid, PublisherUntrusted,
		ManifestNotYetValid, ManifestExpired, ManifestRevoked, RevocationStale, SourceMismatch, MappingNotFound,
		MappingAmbiguous, TargetIncompatible, MappingDowngrade, RuleInvalid, OutputCollision, TypeMismatch,
		ConversionOverflow, UnmappedFieldDenied, CoverageInvalid, ReverseValidationFailed, EvidenceBindingMismatch,
		IdempotencyConflict}, reason)
}

func uniqueTokens(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !tokenPattern.MatchString(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func sortedPaths(values []string) bool {
	previous := ""
	for _, value := range values {
		if !validPath(value, "original") || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func validEmittedHints(values []EmittedEntityHint) bool {
	if len(values) > 512 {
		return false
	}
	for _, value := range values {
		hint := EntityHint{Role: value.Role, IdentifierType: value.IdentifierType, Normalization: value.Normalization,
			ConfidenceCeilingMillionths: value.ConfidenceCeilingMillionths}
		if !tokenPattern.MatchString(value.RuleID) || !validPath(value.OutputPath, outputRoot(value.OutputPath)) ||
			!digestPattern.MatchString(value.SourceFieldDigest) || !validEntityHint(&hint, String) && !validEntityHint(&hint, Integer) {
			return false
		}
	}
	return true
}

func validReverseResults(values []ReverseResult) bool {
	if len(values) > 512 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !tokenPattern.MatchString(value.RuleID) || !digestPattern.MatchString(value.SourcePathDigest) ||
			!digestPattern.MatchString(value.OutputPathDigest) || !slices.Contains([]string{"passed", "not_applicable"}, value.Result) {
			return false
		}
		if _, exists := seen[value.RuleID]; exists {
			return false
		}
		seen[value.RuleID] = struct{}{}
	}
	return true
}

func outputRoot(path string) string {
	if len(path) >= 4 && path[:4] == "ecs." {
		return "ecs"
	}
	return "ocsf"
}

func validTimestampValue(value string) bool {
	_, ok := parseTimestamp(value)
	return ok
}

func formatMappingTime(value time.Time) string { return value.UTC().Format(timestampLayout) }
