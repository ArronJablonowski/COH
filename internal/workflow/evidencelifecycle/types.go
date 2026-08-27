// Package evidencelifecycle owns governed signed evidence package and
// retention, hold, and physical-disposition orchestration.
package evidencelifecycle

import (
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	CommandSchemaVersion                = "coh.evidence-lifecycle-command/v1"
	ExportManifestSchemaVersion         = "coh.evidence-export-manifest/v1"
	DetachedSignatureSchemaVersion      = "coh.evidence-detached-signature/v1"
	PackageHeaderSchemaVersion          = "coh.evidence-package-header/v1"
	ImportVerificationSchemaVersion     = "coh.evidence-import-verification/v1"
	AuthorizationSchemaVersion          = "coh.evidence-lifecycle-authorization/v1"
	DecisionSchemaVersion               = "coh.evidence-lifecycle-decision/v1"
	ProgressSchemaVersion               = "coh.evidence-lifecycle-progress/v1"
	DispositionAttestationSchemaVersion = "coh.evidence-disposition-attestation/v1"
	RecordSchemaVersion                 = "coh.evidence-lifecycle-record/v1"
	ReceiptSchemaVersion                = "coh.evidence-lifecycle-receipt/v1"
	PackageVersion                      = "coh.evidence-package/v1"
	ContractVersion                     = "1.0.0"
	PackageMagic                        = "COHEVPKG1"
	SigningAlgorithm                    = "ed25519"
	NoCompression                       = "none"
)

type Operation string

const (
	Export      Operation = "export"
	Import      Operation = "import"
	PlaceHold   Operation = "place_hold"
	ReleaseHold Operation = "release_hold"
	Delete      Operation = "delete"
)

type Phase string

const (
	Planned      Phase = "planned"
	Quarantined  Phase = "quarantined"
	Verified     Phase = "verified"
	Authorized   Phase = "authorized"
	Packaged     Phase = "packaged"
	Published    Phase = "published"
	CaseRecorded Phase = "case_recorded"
	Tombstoned   Phase = "tombstoned"
	Disposed     Phase = "disposed"
	Custodied    Phase = "custodied"
	Completed    Phase = "completed"
)

type ArtifactRole string

const (
	SourceArtifact   ArtifactRole = "source"
	DerivedArtifact  ArtifactRole = "derived"
	ImportedArtifact ArtifactRole = "imported"
)

type DecisionOutcome string

const (
	Allow DecisionOutcome = "allow"
	Deny  DecisionOutcome = "deny"
)

type DecisionReason string

const (
	ReasonAuthorized             DecisionReason = "authorized"
	ReasonInvalidInput           DecisionReason = "invalid_input"
	ReasonCaseNotFound           DecisionReason = "case_not_found"
	ReasonCaseStateDenied        DecisionReason = "case_state_denied"
	ReasonArtifactNotFound       DecisionReason = "artifact_not_found"
	ReasonArtifactInvalid        DecisionReason = "artifact_invalid"
	ReasonLineageInvalid         DecisionReason = "lineage_invalid"
	ReasonPackageInvalid         DecisionReason = "package_invalid"
	ReasonPackageOversized       DecisionReason = "package_oversized"
	ReasonMediaTypeDenied        DecisionReason = "media_type_denied"
	ReasonSignatureInvalid       DecisionReason = "signature_invalid"
	ReasonSigningKeyInvalid      DecisionReason = "signing_key_invalid"
	ReasonCheckpointInvalid      DecisionReason = "checkpoint_invalid"
	ReasonVerificationIncomplete DecisionReason = "verification_incomplete"
	ReasonAuthorityDenied        DecisionReason = "authority_denied"
	ReasonApprovalRequired       DecisionReason = "approval_required"
	ReasonApprovalInvalid        DecisionReason = "approval_invalid"
	ReasonRevoked                DecisionReason = "revoked"
	ReasonStaleActor             DecisionReason = "stale_actor"
	ReasonStaleCase              DecisionReason = "stale_case"
	ReasonStaleCustody           DecisionReason = "stale_custody"
	ReasonRetentionActive        DecisionReason = "retention_active"
	ReasonLegalHoldActive        DecisionReason = "legal_hold_active"
	ReasonHoldReleaseIncomplete  DecisionReason = "hold_release_incomplete"
	ReasonChangedReplay          DecisionReason = "changed_replay"
	ReasonDispositionFailed      DecisionReason = "disposition_failed"
)

type VerificationOutcome string

const (
	VerificationValid      VerificationOutcome = "valid"
	VerificationInvalid    VerificationOutcome = "invalid"
	VerificationIncomplete VerificationOutcome = "incomplete"
)

type VerificationReason string

const (
	VerifySuccess           VerificationReason = "verified"
	VerifyInvalidHeader     VerificationReason = "invalid_header"
	VerifyInvalidSchema     VerificationReason = "invalid_schema"
	VerifyInvalidScope      VerificationReason = "invalid_scope"
	VerifyInvalidBounds     VerificationReason = "invalid_bounds"
	VerifyInvalidMediaType  VerificationReason = "invalid_media_type"
	VerifyCompressedInput   VerificationReason = "compressed_input"
	VerifyInvalidSignature  VerificationReason = "invalid_signature"
	VerifyUnknownKey        VerificationReason = "unknown_key"
	VerifyRevokedKey        VerificationReason = "revoked_key"
	VerifyExpiredManifest   VerificationReason = "expired_manifest"
	VerifyInvalidArtifact   VerificationReason = "invalid_artifact"
	VerifyInvalidLineage    VerificationReason = "invalid_lineage"
	VerifyInvalidComponent  VerificationReason = "invalid_component"
	VerifyInvalidCustody    VerificationReason = "invalid_custody"
	VerifyInvalidCheckpoint VerificationReason = "invalid_checkpoint"
	VerifyTrailingData      VerificationReason = "trailing_data"
	VerifyTruncatedInput    VerificationReason = "truncated_input"
)

type PackageLimits struct {
	MaximumManifestBytes  int64
	MaximumSignatureBytes int64
	MaximumArtifacts      uint16
	MaximumArtifactBytes  int64
	MaximumPackageBytes   int64
}

type CustodyHead struct {
	Case         domain.CaseRef
	Sequence     uint64
	ChainHash    string
	LastRecordAt *time.Time
}

type EvidenceReference struct {
	Artifact                 domain.ArtifactRef
	Manifest                 domain.ArtifactRef
	ManifestProvenanceDigest string
	IngestionReceiptDigest   string
}

type Component struct {
	Kind    string
	Name    string
	Version string
	Digest  string
}

type ManifestArtifact struct {
	Ordinal                uint16
	Role                   ArtifactRole
	Reference              EvidenceReference
	ParentArtifactDigests  []string
	ParentManifestDigests  []string
	RedactionReceiptDigest *string
	MappingDigest          *string
}

type Command struct {
	SchemaVersion        string
	ContractVersion      string
	RequestID            string
	IdempotencyKey       string
	Operation            Operation
	Case                 domain.CaseRef
	ActorID              string
	ActorRevision        uint64
	ArtifactSetDigest    *string
	PackageDigest        *string
	SourceDigest         *string
	PurposeDigest        *string
	DestinationDigest    *string
	ReasonDigest         *string
	ApprovalDigest       *string
	PolicyDigest         string
	ExpectedCaseRevision uint64
	ExpectedCustodyHead  CustodyHead
	Limits               PackageLimits
	Deadline             time.Time
}

type ExportManifest struct {
	SchemaVersion            string
	ContractVersion          string
	ManifestID               string
	PackageVersion           string
	Case                     domain.CaseRef
	CaseRevision             uint64
	Classification           string
	ActorID                  string
	ActorRevision            uint64
	PurposeDigest            string
	DestinationDigest        string
	Artifacts                []ManifestArtifact
	ArtifactSetDigest        string
	Components               []Component
	PolicyDigest             string
	DecisionDigest           string
	ApprovalDigest           string
	RevocationDigest         string
	CustodyFromSequence      uint64
	CustodyToSequence        uint64
	CustodyReportDigest      string
	AuditCheckpointID        string
	AuditCheckpointDigest    string
	AuditCheckpointSequence  uint64
	AuditSigningKeyRevision  uint64
	AuditProofDigest         string
	SigningAlgorithm         string
	SigningKeyID             string
	SigningKeyRevision       uint64
	Compression              string
	Limits                   PackageLimits
	CreatedAt                time.Time
	ValidUntil               time.Time
	IdempotencyDigest        string
	PreviousProvenanceDigest string
	ManifestDigest           string
}

type DetachedSignature struct {
	SchemaVersion   string
	ContractVersion string
	Algorithm       string
	KeyID           string
	KeyRevision     uint64
	ManifestDigest  string
	Signature       string
}

type PackageHeader struct {
	SchemaVersion   string
	ContractVersion string
	Magic           string
	PackageVersion  string
	Compression     string
	ManifestLength  int64
	SignatureLength int64
	ArtifactCount   uint16
	PackageLength   int64
	HeaderDigest    string
}
