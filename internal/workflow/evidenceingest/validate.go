package evidenceingest

import (
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const maximumArtifactBytes = int64(1 << 30)

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern     = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	mediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`)
)

func validateCommand(value Command, now time.Time) error {
	if err := validateCommandShape(value); err != nil {
		return err
	}
	if !value.Deadline.After(now) {
		return newError(InvalidInput, "command_deadline_invalid", false, nil)
	}
	if value.Source.CollectedAt.After(now.Add(5 * time.Minute)) {
		return newError(Denied, "collection_time_invalid", false, nil)
	}
	return nil
}

func validateCommandShape(value Command) error {
	if value.SchemaVersion != CommandSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey, 1, 256) ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 ||
		value.ActorRevision > math.MaxInt64 || !digestPattern.MatchString(value.ExpectedDigest) ||
		value.ExpectedLength <= 0 || value.ExpectedLength > maximumArtifactBytes ||
		!mediaTypePattern.MatchString(value.MediaType) || !validClassification(value.Classification) ||
		validateSource(value.Source) != nil || !tokenPattern.MatchString(value.KeyProfile) ||
		!digestPattern.MatchString(value.KeyProfileDigest) || !digestPattern.MatchString(value.PolicyDigest) ||
		validateTransport(value.Transport) != nil || !validTime(value.Deadline) {
		return newError(InvalidInput, "command_invalid", false, nil)
	}
	if len(value.ParentArtifacts) > 128 || len(value.ParentArtifacts) != len(value.ParentManifestDigests) ||
		len(value.Components) > 64 || !artifactsSortedUnique(value.ParentArtifacts) ||
		!digestsSortedUnique(value.ParentManifestDigests) || !componentsSortedUnique(value.Components) {
		return newError(InvalidInput, "lineage_invalid", false, nil)
	}
	for _, artifact := range value.ParentArtifacts {
		if !validArtifact(artifact) {
			return newError(InvalidInput, "parent_artifact_invalid", false, nil)
		}
	}
	for _, component := range value.Components {
		if !validComponent(component) {
			return newError(InvalidInput, "component_invalid", false, nil)
		}
	}
	if value.Source.Kind == DerivedSource && len(value.ParentArtifacts) == 0 {
		return newError(InvalidInput, "derived_lineage_required", false, nil)
	}
	return nil
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
		value.CaseRevision == 0 || value.CaseRevision > math.MaxInt64 ||
		(value.CaseState != "open" && value.CaseState != "closed") ||
		!validClassification(value.CaseClassification) || !digestPattern.MatchString(value.CaseProvenanceDigest) ||
		classificationRank(value.Command.Classification) > classificationRank(value.CaseClassification) {
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
		!digestPattern.MatchString(value.AuthorizationDigest) || !digestPattern.MatchString(value.IntentDigest) ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 ||
		value.ActorRevision > math.MaxInt64 || !digestPattern.MatchString(value.ArtifactDigest) ||
		value.ArtifactLength <= 0 || value.ArtifactLength > maximumArtifactBytes ||
		!digestPattern.MatchString(value.PolicyDigest) || !digestPattern.MatchString(value.KeyProfileDigest) ||
		!digestPattern.MatchString(value.TransportDigest) || !digestPattern.MatchString(value.RevocationDigest) ||
		(value.Outcome != "allow" && value.Outcome != "deny") || !tokenPattern.MatchString(value.ReasonCode) ||
		!validTime(value.IssuedAt) || !validTime(value.ExpiresAt) || !value.ExpiresAt.After(value.IssuedAt) ||
		value.Revision == 0 || value.Revision > math.MaxInt64 {
		return newError(Denied, "decision_invalid", false, nil)
	}
	return nil
}

func validateManifest(value ArtifactManifest) error {
	if err := validateManifestShape(value, true); err != nil {
		return err
	}
	want, err := ManifestProvenanceDigest(value)
	if err != nil || want != value.ProvenanceDigest {
		return newError(Denied, "manifest_provenance_invalid", false, err)
	}
	return nil
}

func validateManifestShape(value ArtifactManifest, bound bool) error {
	if value.SchemaVersion != ManifestSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.ManifestID) || !validCase(value.Case) || !validArtifact(value.Artifact) ||
		validateSource(value.Source) != nil || len(value.ParentArtifacts) > 128 ||
		len(value.ParentArtifacts) != len(value.ParentManifestDigests) ||
		!artifactsSortedUnique(value.ParentArtifacts) || !digestsSortedUnique(value.ParentManifestDigests) ||
		len(value.Components) > 64 || !componentsSortedUnique(value.Components) ||
		!uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		!allDigests(value.PolicyDigest, value.AuthorizationDigest, value.DecisionDigest, value.RevocationDigest,
			value.TransportDigest, value.EncryptionContextDigest, value.AuditEventDigest) ||
		pointerDigestValid(value.PreviousProvenanceDigest) != nil ||
		(bound && !digestPattern.MatchString(value.ProvenanceDigest)) || (!bound && value.ProvenanceDigest != "") ||
		!validTime(value.CreatedAt) || value.Revision != 1 {
		return newError(Denied, "manifest_invalid", false, nil)
	}
	for _, artifact := range value.ParentArtifacts {
		if !validArtifact(artifact) {
			return newError(Denied, "manifest_parent_invalid", false, nil)
		}
	}
	for _, component := range value.Components {
		if !validComponent(component) {
			return newError(Denied, "manifest_component_invalid", false, nil)
		}
	}
	if value.Source.Kind == DerivedSource && len(value.ParentArtifacts) == 0 {
		return newError(Denied, "manifest_lineage_invalid", false, nil)
	}
	return nil
}

func validateEncryptedObject(value EncryptedObject) error {
	if value.SchemaVersion != EncryptedObjectSchemaVersion || value.ContractVersion != ContractVersion ||
		!validStatus(value.Status) || !validCase(value.Case) || !digestPattern.MatchString(value.PlaintextDigest) ||
		value.PlaintextLength <= 0 || value.PlaintextLength > maximumArtifactBytes ||
		!digestPattern.MatchString(value.CiphertextDigest) || value.CiphertextLength <= value.PlaintextLength ||
		!mediaTypePattern.MatchString(value.MediaType) || !validClassification(value.Classification) ||
		value.EncryptionFormat != EncryptionFormatVersion || value.ChunkSize < 4096 || value.ChunkSize > 1<<20 ||
		value.ChunkCount == 0 || value.ChunkCount != uint64((value.PlaintextLength+int64(value.ChunkSize)-1)/int64(value.ChunkSize)) ||
		!tokenPattern.MatchString(value.KeyReference) || value.KeyRevision == 0 || value.KeyRevision > math.MaxInt64 ||
		value.KeyAlgorithm != "aes-256-gcm" || !allDigests(value.WrappedKeyDigest, value.EncryptionContextDigest,
		value.LocatorDigest) || !validTime(value.CreatedAt) {
		return newError(Denied, "encrypted_object_invalid", false, nil)
	}
	return nil
}

func validatePublishedObject(value PublishedObject) error {
	if !validCase(value.Case) || !digestPattern.MatchString(value.PlaintextDigest) ||
		value.PlaintextLength <= 0 || value.PlaintextLength > maximumArtifactBytes ||
		!digestPattern.MatchString(value.CiphertextDigest) || value.CiphertextLength <= value.PlaintextLength ||
		value.EncryptionFormat != EncryptionFormatVersion ||
		!allDigests(value.EncryptionContextDigest, value.LocatorDigest) {
		return newError(Denied, "published_object_invalid", false, nil)
	}
	return nil
}

func validatePendingObject(value PendingObject) error {
	if (value.Role != ArtifactPublication && value.Role != ManifestPublication) || !validCase(value.Case) ||
		!digestPattern.MatchString(value.PlaintextDigest) || value.PlaintextLength <= 0 ||
		value.PlaintextLength > maximumArtifactBytes || !mediaTypePattern.MatchString(value.MediaType) ||
		!validClassification(value.Classification) ||
		!allDigests(value.EncryptionContextDigest, value.LocatorDigest) || !validTime(value.CreatedAt) {
		return newError(Denied, "pending_object_invalid", false, nil)
	}
	if value.Role == ManifestPublication && value.MediaType != manifestMediaType {
		return newError(Denied, "pending_manifest_invalid", false, nil)
	}
	return nil
}

// ValidatePendingObject validates the stable reconciliation identity exposed
// to persistence adapters without exposing ciphertext or key material.
func ValidatePendingObject(value PendingObject) error { return validatePendingObject(value) }

func validateReceipt(value Receipt) error {
	if err := validateReceiptShape(value, true); err != nil {
		return err
	}
	want, err := ReceiptBindingDigest(value)
	if err != nil || want != value.ReceiptDigest {
		return newError(Denied, "receipt_digest_invalid", false, err)
	}
	return nil
}

func validateReceiptShape(value Receipt, bound bool) error {
	if value.SchemaVersion != ReceiptSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) ||
		value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		!allDigests(value.IntentDigest, value.IdempotencyDigest, value.AuthorizationDigest, value.DecisionDigest,
			value.RevocationDigest, value.TransportDigest, value.ManifestProvenanceDigest, value.AuditEventDigest) ||
		!validArtifact(value.Artifact) || !validArtifact(value.Manifest) ||
		validatePublishedObject(value.EncryptedArtifact) != nil || validatePublishedObject(value.EncryptedManifest) != nil ||
		value.Manifest.MediaType != "application/vnd.coh.artifact-manifest+json" ||
		value.Case != value.EncryptedArtifact.Case || value.Case != value.EncryptedManifest.Case ||
		value.Artifact.Digest != value.EncryptedArtifact.PlaintextDigest ||
		value.Artifact.Length != value.EncryptedArtifact.PlaintextLength ||
		value.Manifest.Digest != value.EncryptedManifest.PlaintextDigest ||
		value.Manifest.Length != value.EncryptedManifest.PlaintextLength || !validTime(value.CreatedAt) ||
		(bound && !digestPattern.MatchString(value.ReceiptDigest)) || (!bound && value.ReceiptDigest != "") {
		return newError(Denied, "receipt_invalid", false, nil)
	}
	return nil
}

func validateSource(value SourceInput) error {
	if !validSourceKind(value.Kind) || !validOpaque(value.Identity, 1, 1024) ||
		!digestPattern.MatchString(value.IdentityDigest) || value.IdentityDigest != SourceIdentityDigest(value.Identity) ||
		!tokenPattern.MatchString(value.CollectionMethod) || !validOpaque(value.CollectionMethodVersion, 1, 256) ||
		!validTime(value.CollectedAt) || (value.SourceTime != nil && value.SourceRange != nil) {
		return newError(InvalidInput, "source_invalid", false, nil)
	}
	if value.SourceTime != nil && !validObservedTime(*value.SourceTime) {
		return newError(InvalidInput, "source_time_invalid", false, nil)
	}
	if value.SourceRange != nil && (!validObservedTime(value.SourceRange.Start) ||
		!validObservedTime(value.SourceRange.End) || !value.SourceRange.End.Value.After(value.SourceRange.Start.Value)) {
		return newError(InvalidInput, "source_range_invalid", false, nil)
	}
	return nil
}

func validateTransport(value TransportContext) error {
	if (value.Mode != InProcess && value.Mode != MTLS) ||
		!allDigests(value.PeerIdentityDigest, value.ChannelBindingDigest) {
		return newError(InvalidInput, "transport_invalid", false, nil)
	}
	return nil
}

func validObservedTime(value ObservedTime) bool {
	return validTime(value.Value) && value.OriginalOffsetMinutes >= -840 && value.OriginalOffsetMinutes <= 840 &&
		validPrecision(value.Precision) && value.UncertaintyNanos <= uint64(24*time.Hour)
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && mediaTypePattern.MatchString(value.MediaType) &&
		validClassification(value.Classification) && value.Length > 0 && value.Length <= maximumArtifactBytes
}

func validComponent(value ComponentVersion) bool {
	return validComponentKind(value.Kind) && tokenPattern.MatchString(value.Name) &&
		validOpaque(value.Version, 1, 256) && digestPattern.MatchString(value.Digest)
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func allDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func pointerDigestValid(value *string) error {
	if value != nil && !digestPattern.MatchString(*value) {
		return newError(InvalidInput, "optional_digest_invalid", false, nil)
	}
	return nil
}

func artifactsSortedUnique(values []domain.ArtifactRef) bool {
	return slices.IsSortedFunc(values, func(left, right domain.ArtifactRef) int {
		return strings.Compare(artifactIdentity(left), artifactIdentity(right))
	}) && !hasDuplicateArtifacts(values)
}

func componentsSortedUnique(values []ComponentVersion) bool {
	return slices.IsSortedFunc(values, func(left, right ComponentVersion) int {
		return strings.Compare(componentIdentity(left), componentIdentity(right))
	}) && !hasDuplicateComponents(values)
}

func digestsSortedUnique(values []string) bool {
	return slices.IsSorted(values) && !hasDuplicateStrings(values)
}

func artifactIdentity(value domain.ArtifactRef) string {
	return value.Digest + "\x00" + value.MediaType + "\x00" + value.Classification
}
func componentIdentity(value ComponentVersion) string {
	return string(value.Kind) + "\x00" + value.Name + "\x00" + value.Version + "\x00" + value.Digest
}
func hasDuplicateArtifacts(values []domain.ArtifactRef) bool {
	for index := 1; index < len(values); index++ {
		if artifactIdentity(values[index-1]) == artifactIdentity(values[index]) {
			return true
		}
	}
	return false
}
func hasDuplicateComponents(values []ComponentVersion) bool {
	for index := 1; index < len(values); index++ {
		if componentIdentity(values[index-1]) == componentIdentity(values[index]) {
			return true
		}
	}
	return false
}
func hasDuplicateStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func validStatus(value Status) bool {
	return value == Staged || value == Verified || value == Published
}
func validClassification(value string) bool { return classificationRank(value) != 0 }
func classificationRank(value string) int {
	switch value {
	case "public":
		return 1
	case "internal":
		return 2
	case "confidential":
		return 3
	case "restricted":
		return 4
	default:
		return 0
	}
}
func validSourceKind(value SourceKind) bool {
	return value == UploadSource || value == ConnectorSource || value == QuerySource || value == ToolSource ||
		value == ModelSource || value == DerivedSource || value == ImportSource
}
func validComponentKind(value ComponentKind) bool {
	return value == ToolComponent || value == QueryComponent || value == ModelComponent
}
func validPrecision(value TimePrecision) bool {
	return value == NanosecondPrecision || value == MicrosecondPrecision || value == MillisecondPrecision ||
		value == SecondPrecision || value == MinutePrecision || value == DayPrecision || value == UnknownPrecision
}
