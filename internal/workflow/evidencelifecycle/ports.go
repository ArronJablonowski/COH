package evidencelifecycle

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type CaseSnapshot struct {
	Case             domain.CaseRef
	State            string
	Classification   string
	Revision         uint64
	RetainUntil      time.Time
	LegalHold        bool
	ProvenanceDigest string
}

type LifecycleRequest struct {
	Operation            Operation
	Case                 domain.CaseRef
	ActorID              string
	ActorRevision        uint64
	ExpectedCaseRevision uint64
	ManifestDigest       *string
	ReasonDigest         *string
	PolicyDigest         string
	IdempotencyDigest    string
	Deadline             time.Time
}

type LifecycleProof struct {
	Operation        Operation
	Case             domain.CaseRef
	Revision         uint64
	LegalHold        bool
	ReceiptDigest    string
	ProvenanceDigest string
}

type VerifiedEvidenceSet struct {
	Case               domain.CaseRef
	Artifacts          []ManifestArtifact
	Components         []Component
	ArtifactSetDigest  string
	LineageDigest      string
	ComponentSetDigest string
}

type RedactionProof struct {
	ArtifactDigest   string
	ReceiptDigest    string
	MappingDigest    string
	ProvenanceDigest string
}

type CustodyRequest struct {
	Operation                    Operation
	Phase                        Phase
	Case                         domain.CaseRef
	ActorID                      string
	ActorRevision                uint64
	ArtifactSetDigest            string
	ManifestDigest               *string
	PackageDigest                *string
	PurposeDigest                *string
	DestinationDigest            *string
	ReasonDigest                 *string
	SignatureDigest              *string
	LifecycleReceiptDigest       *string
	PriorAuthorizationDigest     *string
	DispositionAttestationDigest *string
	PolicyDigest                 string
	ExpectedCaseRevision         uint64
	ExpectedHead                 CustodyHead
	Deadline                     time.Time
}

type CustodyProof struct {
	ReceiptDigest string
	RecordDigest  string
	AuditDigest   string
	Head          CustodyHead
}

type CustodyVerification struct {
	FromSequence                 uint64
	ToSequence                   uint64
	Head                         CustodyHead
	CheckpointID                 string
	CheckpointDigest             string
	CheckpointSequence           uint64
	CheckpointSigningKeyRevision uint64
	CheckpointProofDigest        string
	ReportDigest                 string
}

type SignRequest struct {
	ManifestDigest string
	CanonicalBytes []byte
	KeyID          string
	KeyRevision    uint64
	DecisionDigest string
}

type VerifySignatureRequest struct {
	ManifestDigest      string
	CanonicalBytes      []byte
	Signature           DetachedSignature
	TrustSnapshotDigest string
	RevocationDigest    string
	At                  time.Time
}

type PackageBuildRequest struct {
	Manifest  ExportManifest
	Signature DetachedSignature
	Evidence  VerifiedEvidenceSet
	Deadline  time.Time
}

type QuarantinedPackage struct {
	Reference       string
	Header          PackageHeader
	HeaderDigest    string
	PackageDigest   string
	PackageLength   int64
	ManifestDigest  string
	SignatureDigest string
}

type ImportRequest struct {
	Reference    string
	SourceDigest string
	Limits       PackageLimits
	Deadline     time.Time
}

type VerifiedImport struct {
	Package      QuarantinedPackage
	Manifest     ExportManifest
	Signature    DetachedSignature
	Verification ImportVerification
}

type ImportPublicationRequest struct {
	Case          domain.CaseRef
	ActorID       string
	ActorRevision uint64
	Verified      VerifiedImport
	PolicyDigest  string
	Deadline      time.Time
}

type PublishedImport struct {
	Artifacts []EvidenceReference
	Progress  []ArtifactProgress
}

type DispositionRequest struct {
	Case                              domain.CaseRef
	OperationID                       string
	ArtifactSetDigest                 string
	Evidence                          VerifiedEvidenceSet
	AuthorizationCustodyReceiptDigest string
	LifecycleReceiptDigest            string
	Deadline                          time.Time
}

type Authority interface {
	AuthorizeEvidenceLifecycle(context.Context, AuthorizationRequest) (Decision, error)
}

type CaseStore interface {
	LoadCase(context.Context, domain.CaseRef) (CaseSnapshot, bool, error)
	ResolveLifecycleReceipt(context.Context, domain.CaseRef, string) (LifecycleProof, bool, error)
	HasIncompleteHoldRelease(context.Context, domain.CaseRef) (bool, error)
}

type CaseLifecycle interface {
	ApplyCaseOperation(context.Context, LifecycleRequest) (LifecycleProof, error)
}

type EvidenceResolver interface {
	ResolveEvidenceSet(context.Context, domain.CaseRef, string) (VerifiedEvidenceSet, error)
}

type RedactionResolver interface {
	VerifyRedactionReceipts(context.Context, domain.CaseRef, VerifiedEvidenceSet) ([]RedactionProof, error)
}

type Custody interface {
	LoadCustodyHead(context.Context, domain.CaseRef) (CustodyHead, error)
	RecordLifecycle(context.Context, CustodyRequest) (CustodyProof, error)
	VerifyLifecycle(context.Context, domain.CaseRef, uint64, uint64) (CustodyVerification, error)
}

type Signer interface {
	SignManifest(context.Context, SignRequest) (DetachedSignature, error)
}

type SignatureVerifier interface {
	VerifyDetachedSignature(context.Context, VerifySignatureRequest) error
}

type PackageWriter interface {
	BuildPackage(context.Context, PackageBuildRequest) (QuarantinedPackage, error)
	RecoverPackage(context.Context, domain.CaseRef, string) (QuarantinedPackage, bool, error)
	VerifyPackage(context.Context, QuarantinedPackage, PackageLimits) error
}

type PackageReader interface {
	VerifyImport(context.Context, ImportRequest) (VerifiedImport, error)
}

type Publisher interface {
	PublishImport(context.Context, ImportPublicationRequest) (PublishedImport, error)
}

type Disposer interface {
	DisposeEvidence(context.Context, DispositionRequest) (DispositionAttestation, error)
	RecoverDisposition(context.Context, domain.CaseRef, string) (DispositionAttestation, bool, error)
}

type Store interface {
	Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error)
	LoadProgress(context.Context, domain.CaseRef, string) (Progress, bool, error)
	Advance(context.Context, string, string, Progress) (Progress, bool, error)
	Commit(context.Context, string, string, Progress, Record, Receipt) (Receipt, bool, error)
}

type Auditor interface {
	AppendLifecycleEvent(context.Context, tamperaudit.Event) error
	VerifyLifecycleEvent(context.Context, domain.CaseRef, string, string) error
}

type Clock interface{ Now() time.Time }
