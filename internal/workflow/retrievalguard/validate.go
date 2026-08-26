package retrievalguard

import (
	"context"
	"math"
	"regexp"
	"slices"
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

func validateRequest(value Request, now time.Time) error {
	if err := validateRequestShape(value); err != nil {
		return err
	}
	if !value.Deadline.After(now) {
		return newError(InvalidInput, "request_deadline_invalid", false, nil)
	}
	return nil
}

func validateRequestShape(value Request) error {
	if value.SchemaVersion != RequestSchemaVersion || value.ContractVersion != ContractVersion || !uuidPattern.MatchString(value.RequestID) ||
		!validOpaque(value.IdempotencyKey, 1, 256) || !validCase(value.Case) || !uuidPattern.MatchString(value.TaskID) ||
		!uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		validateSource(value.Source) != nil || validateProfile(value.Profile) != nil || value.Source.Artifact.Length > value.Profile.MaximumBytes ||
		!slices.Contains(value.Profile.AllowedMediaTypes, value.Source.Artifact.MediaType) || !digestPattern.MatchString(value.PolicyDigest) || !validTime(value.Deadline) {
		return newError(InvalidInput, "request_invalid", false, nil)
	}
	return nil
}

func validateSource(value Source) error {
	if !validSourceKind(value.Kind) || value.Trust != UntrustedContent || !validArtifact(value.Artifact, MaximumSourceBytes) || !digestPattern.MatchString(value.ProvenanceDigest) {
		return newError(InvalidInput, "source_invalid", false, nil)
	}
	return nil
}

func validateProfile(value InspectionProfile) error {
	copyValue := cloneProfile(value)
	copyValue.ProfileDigest = ""
	if err := validateProfileShape(copyValue); err != nil {
		return err
	}
	bound, err := ProfileBindingDigest(copyValue)
	if err != nil || bound != value.ProfileDigest {
		return newError(Denied, "profile_digest_invalid", false, nil)
	}
	return nil
}

func validateProfileShape(value InspectionProfile) error {
	if !tokenPattern.MatchString(value.Name) || value.Revision == 0 || value.Revision > math.MaxInt64 || value.MaximumBytes <= 0 || value.MaximumBytes > MaximumSourceBytes ||
		len(value.AllowedMediaTypes) == 0 || len(value.AllowedMediaTypes) > 16 || !slices.IsSorted(value.AllowedMediaTypes) || hasDuplicateStrings(value.AllowedMediaTypes) ||
		!value.DenyActiveFormats || !value.RedactSecrets || !value.NeutralizeDirectives || value.ProfileDigest != "" {
		return newError(InvalidInput, "profile_invalid", false, nil)
	}
	for _, mediaType := range value.AllowedMediaTypes {
		if !mediaPattern.MatchString(mediaType) {
			return newError(InvalidInput, "profile_media_type_invalid", false, nil)
		}
	}
	return nil
}

func validateAuthorization(value AuthorizationRequest) error {
	request := Request{SchemaVersion: RequestSchemaVersion, ContractVersion: ContractVersion, RequestID: value.RequestID, IdempotencyKey: "authorization-binding",
		Case: value.Case, TaskID: value.TaskID, ActorID: value.ActorID, ActorRevision: value.ActorRevision, Source: value.Source, Profile: value.Profile, PolicyDigest: value.PolicyDigest, Deadline: value.Deadline}
	if !digestPattern.MatchString(value.RequestDigest) || validateRequestShape(request) != nil {
		return newError(InvalidInput, "authorization_request_invalid", false, nil)
	}
	return nil
}

func validateDecisionShape(value Decision) error {
	if value.SchemaVersion != DecisionSchemaVersion || value.ContractVersion != ContractVersion || !uuidPattern.MatchString(value.DecisionID) || value.DecisionDigest != "" ||
		!digestPattern.MatchString(value.RequestDigest) || !validCase(value.Case) || !uuidPattern.MatchString(value.TaskID) || !uuidPattern.MatchString(value.ActorID) ||
		value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 || !digestPattern.MatchString(value.PolicyDigest) || !digestPattern.MatchString(value.RevocationDigest) ||
		(value.Outcome != "allow" && value.Outcome != "deny") || !tokenPattern.MatchString(value.ReasonCode) || value.Revision == 0 || value.Revision > math.MaxInt64 ||
		!validTime(value.IssuedAt) || !validTime(value.ExpiresAt) || !value.ExpiresAt.After(value.IssuedAt) {
		return newError(Denied, "decision_invalid", false, nil)
	}
	return nil
}

func validateInspection(value InspectionResult, request Request) error {
	if value.SourceDigest != request.Source.Artifact.Digest || value.SourceProvenanceDigest != request.Source.ProvenanceDigest ||
		value.Trust != UntrustedContent || !value.Complete || !validArtifact(value.Sanitized, request.Profile.MaximumBytes) ||
		value.Sanitized.MediaType != "application/json" || value.Sanitized.Classification != request.Source.Artifact.Classification ||
		value.Sanitized.Digest == request.Source.Artifact.Digest || !digestPattern.MatchString(value.InspectorDigest) || validateFindings(value.Findings, value.FindingsDigest) != nil {
		return newError(Denied, "inspection_invalid", false, nil)
	}
	redacted := uint64(0)
	for _, finding := range value.Findings {
		if finding.Code == SecretRedacted {
			redacted += uint64(finding.Count)
		}
	}
	if uint64(value.RedactionCount) < redacted {
		return newError(Denied, "redaction_count_invalid", false, nil)
	}
	return nil
}

func validateFindings(values []Finding, bound string) error {
	if !digestPattern.MatchString(bound) {
		return newError(Denied, "findings_digest_invalid", false, nil)
	}
	if err := validateFindingsShape(values); err != nil {
		return err
	}
	expected, err := FindingsBindingDigest(values)
	if err != nil || expected != bound {
		return newError(Denied, "findings_digest_invalid", false, nil)
	}
	return nil
}
func validateFindingsShape(values []Finding) error {
	if len(values) > MaximumFindings {
		return newError(Denied, "findings_invalid", false, nil)
	}
	prior := ""
	for _, finding := range values {
		current := string(finding.Code)
		if !validFinding(finding.Code) || finding.Count == 0 || current <= prior {
			return newError(Denied, "findings_invalid", false, nil)
		}
		prior = current
	}
	return nil
}

func validateRecord(value Record) error {
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion || validateRequestShape(value.Request) != nil ||
		!digestPattern.MatchString(value.IntentDigest) || !digestPattern.MatchString(value.IdempotencyDigest) || !digestPattern.MatchString(value.DecisionDigest) ||
		!digestPattern.MatchString(value.RevocationDigest) || validateInspection(value.Inspection, value.Request) != nil || !digestPattern.MatchString(value.AuditEventDigest) ||
		value.PreviousProvenanceDigest != value.Request.Source.ProvenanceDigest || !digestPattern.MatchString(value.PreviousProvenanceDigest) ||
		!validTime(value.CreatedAt) || value.CreatedAt.After(value.Request.Deadline) || value.Revision != 1 {
		return newError(Denied, "record_invalid", false, nil)
	}
	intent, err := RequestBindingDigest(value.Request)
	if err != nil || intent != value.IntentDigest || idempotencyDigest(value.Request.IdempotencyKey) != value.IdempotencyDigest {
		return newError(Denied, "record_binding_invalid", false, nil)
	}
	provenance, err := provenanceDigest(value)
	if err != nil || provenance != value.ProvenanceDigest {
		return newError(Denied, "provenance_invalid", false, nil)
	}
	return nil
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID)
}
func validArtifact(value domain.ArtifactRef, maximum int64) bool {
	return digestPattern.MatchString(value.Digest) && mediaPattern.MatchString(value.MediaType) && tokenPattern.MatchString(value.Classification) && value.Length > 0 && value.Length <= maximum
}
func validSourceKind(value SourceKind) bool {
	switch value {
	case LogSource, DocumentSource, FeedSource, QueryOutputSource, ToolOutputSource, ToolErrorSource, MemorySource, ReportSource, AttachmentSource:
		return true
	default:
		return false
	}
}
func validFinding(value FindingCode) bool {
	switch value {
	case InstructionLike, ScopeChangeAttempt, AuthorizationForgery, CredentialRequest, ToolDirective, ExfiltrationAttempt, ActiveContent, EncodedPayload, SecretRedacted:
		return true
	default:
		return false
	}
}
func validTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }
func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}
func hasDuplicateStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func operationContext(parent context.Context, deadline, timeNow time.Time) (context.Context, context.CancelFunc) {
	if current, ok := parent.Deadline(); ok && current.Before(deadline) {
		return context.WithDeadline(parent, current)
	}
	if !deadline.After(timeNow) {
		return context.WithCancel(parent)
	}
	return context.WithDeadline(parent, deadline)
}
