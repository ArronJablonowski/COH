package memorynamespace

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	mediaPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$`)
)

func validatePut(value PutRequest, now time.Time) error {
	if value.SchemaVersion != PutSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !uuidPattern.MatchString(value.ActorID) ||
		!validOpaque(value.IdempotencyKey, 1, 256) || !validNamespace(value.Namespace) ||
		validateScope(value.Namespace, value.Scope) != nil || !tokenPattern.MatchString(value.Key) ||
		!validArtifact(value.Value) || !validValueType(value.Namespace, value.ValueType) ||
		!digestPattern.MatchString(value.PolicyDigest) || value.ExpectedRevision > math.MaxInt64 ||
		!validTime(value.Deadline) || !value.Deadline.After(now) {
		return newError(InvalidInput, "write_request_invalid", false, nil)
	}
	if err := validateRetention(value.Namespace, value.Retention, now); err != nil {
		return err
	}
	if value.Namespace == ReviewedOrganizationMemory {
		if err := validateReview(value.Review, value.ActorID, now); err != nil {
			return err
		}
	} else if value.Review != (Review{}) {
		return newError(Denied, "review_cross_class", false, nil)
	}
	if (value.Namespace == SessionMemory || value.Namespace == AnalystPreferenceMemory) && value.ActorID != value.Scope.SubjectActorID {
		return newError(Denied, "memory_owner_required", false, nil)
	}
	return nil
}

func validateGet(value GetRequest, now time.Time) error {
	if value.SchemaVersion != GetSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !uuidPattern.MatchString(value.ActorID) ||
		!validNamespace(value.Namespace) || validateScope(value.Namespace, value.Scope) != nil ||
		!tokenPattern.MatchString(value.Key) || !digestPattern.MatchString(value.PolicyDigest) ||
		!validTime(value.Deadline) || !value.Deadline.After(now) {
		return newError(InvalidInput, "read_request_invalid", false, nil)
	}
	if (value.Namespace == SessionMemory || value.Namespace == AnalystPreferenceMemory) && value.ActorID != value.Scope.SubjectActorID {
		return newError(Denied, "memory_owner_required", false, nil)
	}
	return nil
}

func validateScope(namespace Namespace, value Scope) error {
	if !uuidPattern.MatchString(value.OrganizationID) || !uuidPattern.MatchString(value.TenantID) {
		return newError(InvalidInput, "scope_invalid", false, nil)
	}
	switch namespace {
	case SessionMemory:
		if !uuidPattern.MatchString(value.CaseID) || !uuidPattern.MatchString(value.SessionID) ||
			!uuidPattern.MatchString(value.SubjectActorID) {
			return newError(InvalidInput, "session_scope_invalid", false, nil)
		}
	case CaseMemory:
		if !uuidPattern.MatchString(value.CaseID) || value.SessionID != "" || value.SubjectActorID != "" {
			return newError(InvalidInput, "case_scope_invalid", false, nil)
		}
	case AnalystPreferenceMemory:
		if value.CaseID != "" || value.SessionID != "" || !uuidPattern.MatchString(value.SubjectActorID) {
			return newError(InvalidInput, "analyst_scope_invalid", false, nil)
		}
	case ReviewedOrganizationMemory:
		if value.CaseID != "" || value.SessionID != "" || value.SubjectActorID != "" {
			return newError(InvalidInput, "organization_scope_invalid", false, nil)
		}
	default:
		return newError(InvalidInput, "namespace_invalid", false, nil)
	}
	return nil
}

func validateRetention(namespace Namespace, value RetentionPolicy, now time.Time) error {
	want, maximum := retentionBoundary(namespace)
	if value.Class != want || !digestPattern.MatchString(value.PolicyDigest) || !validTime(value.ExpiresAt) ||
		!value.ExpiresAt.After(now) || value.ExpiresAt.After(now.Add(maximum)) {
		return newError(Denied, "retention_invalid", false, nil)
	}
	return nil
}

func retentionBoundary(namespace Namespace) (string, time.Duration) {
	switch namespace {
	case SessionMemory:
		return "session_ephemeral", 30 * 24 * time.Hour
	case CaseMemory:
		return "case_record", 10 * 365 * 24 * time.Hour
	case AnalystPreferenceMemory:
		return "analyst_preference", 2 * 365 * 24 * time.Hour
	case ReviewedOrganizationMemory:
		return "reviewed_organization", 365 * 24 * time.Hour
	default:
		return "", 0
	}
}

func validateReview(value Review, writer string, now time.Time) error {
	if !uuidPattern.MatchString(value.ReviewID) || !uuidPattern.MatchString(value.ReviewerActorID) ||
		value.ReviewerActorID == writer || value.Revision == 0 || value.Revision > math.MaxInt64 ||
		!digestPattern.MatchString(value.AuthorityDigest) || !validTime(value.ReviewedAt) ||
		value.ReviewedAt.After(now) || !validTime(value.ValidUntil) || !value.ValidUntil.After(now) {
		return newError(Denied, "independent_review_invalid", false, nil)
	}
	return nil
}

func validateRecord(value Record) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion ||
		!validNamespace(value.Namespace) || validateScope(value.Namespace, value.Scope) != nil ||
		!tokenPattern.MatchString(value.Key) || !validArtifact(value.Value) || !validValueType(value.Namespace, value.ValueType) ||
		!validStoredRetention(value.Namespace, value.Retention, value.UpdatedAt) ||
		!uuidPattern.MatchString(value.WriterActorID) || !digestPattern.MatchString(value.PolicyDigest) ||
		!digestPattern.MatchString(value.IntentDigest) || !digestPattern.MatchString(value.IdempotencyDigest) ||
		!digestPattern.MatchString(value.AccessDecisionDigest) || !validTime(value.CreatedAt) ||
		!validTime(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) || value.Revision == 0 || value.Revision > math.MaxInt64 {
		return newError(Denied, "record_invalid", false, nil)
	}
	if value.Revision == 1 && value.PreviousProvenanceDigest != "" || value.Revision > 1 && !digestPattern.MatchString(value.PreviousProvenanceDigest) {
		return newError(Denied, "provenance_chain_invalid", false, nil)
	}
	if value.Namespace == ReviewedOrganizationMemory {
		if !digestPattern.MatchString(value.ReviewDecisionDigest) || validateReview(value.Review, value.WriterActorID, value.UpdatedAt) != nil {
			return newError(Denied, "review_record_invalid", false, nil)
		}
	} else if value.Review != (Review{}) || value.ReviewDecisionDigest != "" {
		return newError(Denied, "review_cross_class", false, nil)
	}
	expected, err := provenanceDigest(value)
	if err != nil || expected != value.ProvenanceDigest {
		return newError(Denied, "provenance_invalid", false, nil)
	}
	return nil
}

func validStoredRetention(namespace Namespace, value RetentionPolicy, writtenAt time.Time) bool {
	want, maximum := retentionBoundary(namespace)
	return value.Class == want && digestPattern.MatchString(value.PolicyDigest) && validTime(value.ExpiresAt) &&
		value.ExpiresAt.After(writtenAt) && !value.ExpiresAt.After(writtenAt.Add(maximum))
}

func validateAccessRequest(value AccessRequest) error {
	if value.SchemaVersion != AccessSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !uuidPattern.MatchString(value.ActorID) ||
		(value.Operation != Read && value.Operation != Write) || !validNamespace(value.Namespace) ||
		validateScope(value.Namespace, value.Scope) != nil || !tokenPattern.MatchString(value.Key) ||
		!digestPattern.MatchString(value.ValueDigest) || !digestPattern.MatchString(value.RetentionDigest) ||
		!digestPattern.MatchString(value.PolicyDigest) || !validTime(value.Deadline) {
		return newError(InvalidInput, "access_request_invalid", false, nil)
	}
	return nil
}

func validateDecisionShape(value Decision) error {
	if value.SchemaVersion != AccessSchemaVersion || value.ContractVersion != ContractVersion ||
		!tokenPattern.MatchString(value.ReasonCode) || !digestPattern.MatchString(value.AccessRequestDigest) ||
		value.DecisionDigest != "" || !validTime(value.DecidedAt) || !validTime(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.DecidedAt) {
		return newError(Denied, "access_decision_invalid", false, nil)
	}
	return nil
}

func validateReviewRequest(value ReviewRequest) error {
	if value.SchemaVersion != ReviewSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !uuidPattern.MatchString(value.ActorID) ||
		!uuidPattern.MatchString(value.WriterActorID) ||
		(value.Operation != Read && value.Operation != Write) || validateScope(ReviewedOrganizationMemory, value.Scope) != nil ||
		!tokenPattern.MatchString(value.Key) || !digestPattern.MatchString(value.ValueDigest) ||
		!digestPattern.MatchString(value.PolicyDigest) || !validTime(value.Deadline) ||
		validateReview(value.Review, value.WriterActorID, value.Review.ReviewedAt) != nil {
		return newError(InvalidInput, "review_request_invalid", false, nil)
	}
	return nil
}

func validateReviewDecisionShape(value ReviewDecision) error {
	if value.SchemaVersion != ReviewSchemaVersion || value.ContractVersion != ContractVersion ||
		!tokenPattern.MatchString(value.ReasonCode) || !digestPattern.MatchString(value.ReviewRequestDigest) ||
		value.DecisionDigest != "" || !validTime(value.DecidedAt) || !validTime(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.DecidedAt) {
		return newError(Denied, "review_decision_invalid", false, nil)
	}
	return nil
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && value.MediaType == "application/json" && mediaPattern.MatchString(value.MediaType) &&
		tokenPattern.MatchString(value.Classification) && value.Length > 0 && value.Length <= 1<<30
}

func validValueType(namespace Namespace, value string) bool {
	switch namespace {
	case SessionMemory:
		return value == "session_state_reference"
	case CaseMemory:
		return value == "case_memory_reference"
	case AnalystPreferenceMemory:
		return value == "analyst_preference_reference"
	case ReviewedOrganizationMemory:
		return value == "reviewed_organization_reference"
	default:
		return false
	}
}

func validNamespace(value Namespace) bool {
	return value == SessionMemory || value == CaseMemory || value == AnalystPreferenceMemory || value == ReviewedOrganizationMemory
}
func validTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }
func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func operationContext(parent context.Context, deadline, now time.Time) (context.Context, context.CancelFunc) {
	if current, ok := parent.Deadline(); ok && current.Before(deadline) {
		return context.WithDeadline(parent, current)
	}
	if !deadline.After(now) {
		return context.WithCancel(parent)
	}
	return context.WithDeadline(parent, deadline)
}
