package custody

import (
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const maximumArtifactBytes = int64(1 << 30)

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`)
)

func validateCommand(value Command, now time.Time) error {
	if err := validateCommandShape(value); err != nil {
		return err
	}
	if !value.Deadline.After(now) {
		return newError(InvalidInput, "command_deadline_invalid", false, nil)
	}
	return nil
}

func validateCommandShape(value Command) error {
	if value.SchemaVersion != CommandSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey, 1, 256) ||
		!validOperation(value.Operation) || !validPhase(value.Phase) || !validCase(value.Case) ||
		!uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		!validEvidence(value.Subject) || !validParents(value.Parents, value.Subject) ||
		!allPointerDigests(value.SourceIdentityDigest, value.PurposeDigest, value.DestinationDigest,
			value.RecipientDigest, value.TransformationDigest, value.RuleDigest, value.ReasonDigest,
			value.MappingDigest, value.ApprovalDigest, value.GoverningDecisionDigest, value.ExternalReceiptDigest,
			value.LifecycleReceiptDigest, value.PriorAuthorizationDigest, value.ArtifactSetDigest) ||
		!digestPattern.MatchString(value.PolicyDigest) || value.ExpectedCaseRevision == 0 ||
		value.ExpectedCaseRevision > math.MaxInt64 || !validHead(value.ExpectedHead) ||
		value.ExpectedHead.Case != value.Case || !validTime(value.Deadline) {
		return newError(InvalidInput, "command_invalid", false, nil)
	}
	if !validOperationFields(value) {
		return newError(InvalidInput, "operation_fields_invalid", false, nil)
	}
	return nil
}

func validOperationFields(value Command) bool {
	parents := len(value.Parents)
	source, purpose := value.SourceIdentityDigest, value.PurposeDigest
	destination, recipient := value.DestinationDigest, value.RecipientDigest
	transformation, rule, reason := value.TransformationDigest, value.RuleDigest, value.ReasonDigest
	mapping, approval, governing := value.MappingDigest, value.ApprovalDigest, value.GoverningDecisionDigest
	external, lifecycle := value.ExternalReceiptDigest, value.LifecycleReceiptDigest
	prior, artifactSet := value.PriorAuthorizationDigest, value.ArtifactSetDigest
	switch value.Operation {
	case Acquire:
		return value.Phase == Completed && parents == 0 && source != nil &&
			allNil(purpose, destination, recipient, transformation, rule, reason, mapping, approval, governing,
				external, lifecycle, prior, artifactSet)
	case Access:
		return value.Phase == Authorized && parents == 0 && purpose != nil &&
			allNil(source, destination, recipient, transformation, rule, reason, mapping, approval, governing,
				external, lifecycle, prior, artifactSet)
	case Transform:
		return value.Phase == Completed && parents > 0 && transformation != nil &&
			allNil(source, purpose, destination, recipient, rule, reason, mapping, approval, governing,
				external, lifecycle, prior, artifactSet)
	case Redact:
		return value.Phase == Completed && parents > 0 && rule != nil && reason != nil &&
			mapping != nil && approval != nil && governing != nil && allNil(source, purpose, destination, recipient,
			transformation, external, lifecycle, prior, artifactSet)
	case Transfer, Export:
		base := parents == 0 && purpose != nil && (destination != nil || recipient != nil) &&
			allNil(source, transformation, rule, reason, mapping, approval, governing, lifecycle, artifactSet)
		return base && (value.Phase == Authorized && allNil(external, prior) ||
			value.Phase == Completed && external != nil && prior != nil)
	case PlaceHold, ReleaseHold:
		return value.Phase == Completed && parents == 0 && reason != nil && lifecycle != nil && artifactSet != nil &&
			allNil(source, purpose, destination, recipient, transformation, rule, mapping, approval, governing, external, prior)
	case Delete:
		base := parents == 0 && reason != nil && artifactSet != nil &&
			allNil(source, purpose, destination, recipient, transformation, rule, mapping, approval, governing)
		return base && (value.Phase == Authorized && allNil(external, prior, lifecycle) ||
			value.Phase == Completed && external != nil && prior != nil && lifecycle != nil)
	default:
		return false
	}
}

func validateAuthorization(value AuthorizationRequest) error {
	if err := validateAuthorizationShape(value, true); err != nil {
		return err
	}
	want, err := AuthorizationBindingDigest(value)
	if err != nil || want != value.AuthorizationDigest {
		return newError(Denied, "authorization_digest_invalid", false, err)
	}
	return nil
}

func validateAuthorizationShape(value AuthorizationRequest, bound bool) error {
	if value.SchemaVersion != AuthorizationSchemaVersion || value.ContractVersion != ContractVersion ||
		(bound && !digestPattern.MatchString(value.AuthorizationDigest)) || (!bound && value.AuthorizationDigest != "") ||
		!digestPattern.MatchString(value.IntentDigest) || validateCommandShape(value.Command) != nil ||
		!validCaseState(value.CaseState) || !validClassification(value.CaseClassification) ||
		value.CaseRevision == 0 || value.CaseRevision > math.MaxInt64 ||
		!allDigests(value.RetentionPolicyDigest, value.CaseProvenanceDigest, value.EvidenceVerifiedDigest) ||
		!validTime(value.RetainUntil) || !validHead(value.CurrentHead) ||
		value.CurrentHead.Case != value.Command.Case || value.CaseRevision < value.Command.ExpectedCaseRevision ||
		value.CurrentHead.Sequence < value.Command.ExpectedHead.Sequence {
		return newError(InvalidInput, "authorization_invalid", false, nil)
	}
	want, err := CommandBindingDigest(value.Command)
	if err != nil || want != value.IntentDigest {
		return newError(Denied, "authorization_intent_invalid", false, err)
	}
	return nil
}

func validateDecision(value Decision) error {
	if err := validateDecisionShape(value, true); err != nil {
		return err
	}
	want, err := DecisionBindingDigest(value)
	if err != nil || want != value.DecisionDigest {
		return newError(Denied, "decision_digest_invalid", false, err)
	}
	return nil
}

func validateDecisionShape(value Decision, bound bool) error {
	if value.SchemaVersion != DecisionSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.DecisionID) ||
		(bound && !digestPattern.MatchString(value.DecisionDigest)) || (!bound && value.DecisionDigest != "") ||
		!allDigests(value.AuthorizationDigest, value.IntentDigest, value.PolicyDigest, value.RevocationDigest) ||
		!validOperation(value.Operation) || !validPhase(value.Phase) || !validCase(value.Case) ||
		!uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		value.ExpectedCaseRevision == 0 || value.ExpectedCaseRevision > math.MaxInt64 ||
		!validHead(value.ExpectedHead) || value.ExpectedHead.Case != value.Case ||
		!validDecisionOutcome(value.Outcome) || !validDecisionReason(value.ReasonCode) ||
		(value.Outcome == Allow) != (value.ReasonCode == ReasonAuthorized) || !validTime(value.IssuedAt) ||
		!validTime(value.ExpiresAt) || !value.ExpiresAt.After(value.IssuedAt) ||
		value.Revision == 0 || value.Revision > math.MaxInt64 {
		return newError(Denied, "decision_invalid", false, nil)
	}
	return nil
}

func validateRecord(value Record) error {
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.CustodyID) || !validCase(value.Case) || value.Sequence == 0 ||
		value.Sequence > math.MaxInt64 || !digestPattern.MatchString(value.PreviousChainHash) ||
		validateCommandShape(value.Command) != nil || value.Command.Case != value.Case ||
		value.Sequence != value.Command.ExpectedHead.Sequence+1 ||
		value.PreviousChainHash != value.Command.ExpectedHead.ChainHash ||
		!allDigests(value.IntentDigest, value.AuthorizationDigest, value.DecisionDigest, value.RevocationDigest,
			value.EvidenceVerifiedDigest, value.ProvenanceDigest, value.AuditEventDigest, value.RecordDigest, value.ChainHash) ||
		!pointerDigest(value.PreviousProvenanceDigest) || !validTime(value.OccurredAt) ||
		(value.Sequence == 1) != (value.PreviousProvenanceDigest == nil) {
		return newError(Denied, "record_invalid", false, nil)
	}
	intent, err := CommandBindingDigest(value.Command)
	if err != nil || intent != value.IntentDigest {
		return newError(Denied, "record_intent_invalid", false, err)
	}
	provenance, err := RecordProvenanceDigest(value)
	if err != nil || provenance != value.ProvenanceDigest {
		return newError(Denied, "record_provenance_invalid", false, err)
	}
	recordDigest, err := RecordBindingDigest(value)
	if err != nil || recordDigest != value.RecordDigest {
		return newError(Denied, "record_digest_invalid", false, err)
	}
	chainHash, err := RecordChainHash(value)
	if err != nil || chainHash != value.ChainHash {
		return newError(Denied, "record_chain_invalid", false, err)
	}
	return nil
}

func validateReceipt(value Receipt) error {
	if value.SchemaVersion != ReceiptSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validCase(value.Case) ||
		!allDigests(value.IdempotencyDigest, value.IntentDigest, value.DecisionDigest, value.RecordDigest,
			value.ChainHash, value.AuditEventDigest, value.ProvenanceDigest) ||
		!uuidPattern.MatchString(value.CustodyID) || value.Sequence == 0 || value.Sequence > math.MaxInt64 ||
		!validTime(value.CreatedAt) || !digestPattern.MatchString(value.ReceiptDigest) {
		return newError(Denied, "receipt_invalid", false, nil)
	}
	want, err := ReceiptBindingDigest(value)
	if err != nil || want != value.ReceiptDigest {
		return newError(Denied, "receipt_digest_invalid", false, err)
	}
	return nil
}

func validParents(values []EvidenceReference, child EvidenceReference) bool {
	if len(values) > 128 {
		return false
	}
	previous := ""
	childKey := evidenceKey(child)
	for _, value := range values {
		key := evidenceKey(value)
		if !validEvidence(value) || key == childKey || previous != "" && key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func validEvidence(value EvidenceReference) bool {
	return validArtifact(value.Artifact) && validArtifact(value.Manifest) &&
		value.Manifest.MediaType == "application/vnd.coh.artifact-manifest+json" &&
		value.Manifest.Classification == value.Artifact.Classification &&
		value.Manifest.Digest != value.Artifact.Digest &&
		allDigests(value.ManifestProvenanceDigest, value.IngestionReceiptDigest)
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && mediaTypePattern.MatchString(value.MediaType) &&
		validClassification(value.Classification) && value.Length > 0 && value.Length <= maximumArtifactBytes
}

func validHead(value Head) bool {
	if !validCase(value.Case) || !digestPattern.MatchString(value.ChainHash) || value.Sequence > math.MaxInt64 {
		return false
	}
	if value.Sequence == 0 {
		return value.ChainHash == GenesisHash && value.LastRecordAt == nil
	}
	return value.ChainHash != GenesisHash && value.LastRecordAt != nil && validTime(*value.LastRecordAt)
}

func sameHead(left, right Head) bool {
	if left.Case != right.Case || left.Sequence != right.Sequence || left.ChainHash != right.ChainHash ||
		(left.LastRecordAt == nil) != (right.LastRecordAt == nil) {
		return false
	}
	return left.LastRecordAt == nil || left.LastRecordAt.Equal(*right.LastRecordAt)
}

func evidenceKey(value EvidenceReference) string {
	return value.Artifact.Digest + "\x00" + value.Manifest.Digest + "\x00" + value.IngestionReceiptDigest
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validClassification(value string) bool {
	return value == "public" || value == "internal" || value == "confidential" || value == "restricted"
}

func validCaseState(value string) bool {
	return value == "open" || value == "closed" || value == "deleted"
}

func validOperation(value Operation) bool {
	switch value {
	case Acquire, Access, Transform, Redact, Transfer, Export, PlaceHold, ReleaseHold, Delete:
		return true
	default:
		return false
	}
}

func validPhase(value Phase) bool { return value == Authorized || value == Completed }

func validDecisionOutcome(value DecisionOutcome) bool { return value == Allow || value == Deny }

func validDecisionReason(value DecisionReason) bool {
	switch value {
	case ReasonAuthorized, ReasonInvalidInput, ReasonCaseNotFound, ReasonCaseStateDenied,
		ReasonArtifactNotFound, ReasonArtifactInvalid, ReasonManifestInvalid, ReasonLineageInvalid,
		ReasonAuthorityDenied, ReasonApprovalRequired, ReasonApprovalInvalid, ReasonRevoked,
		ReasonStaleActor, ReasonStaleCase, ReasonStaleHead, ReasonChangedReplay,
		ReasonRetentionActive, ReasonLegalHoldActive:
		return true
	default:
		return false
	}
}

func validTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func allPointerDigests(values ...*string) bool {
	for _, value := range values {
		if value != nil && !digestPattern.MatchString(*value) {
			return false
		}
	}
	return true
}

func pointerDigest(value *string) bool { return value == nil || digestPattern.MatchString(*value) }

func allDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func allNil(values ...*string) bool {
	for _, value := range values {
		if value != nil {
			return false
		}
	}
	return true
}
