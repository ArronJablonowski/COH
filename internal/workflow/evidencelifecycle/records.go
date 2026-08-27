package evidencelifecycle

import (
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

type ImportVerification struct {
	SchemaVersion         string
	ContractVersion       string
	VerificationID        string
	SourceDigest          string
	PackageDigest         string
	HeaderDigest          string
	ManifestDigest        string
	SignatureDigest       string
	SigningKeyID          string
	SigningKeyRevision    uint64
	TrustSnapshotDigest   string
	RevocationDigest      string
	ArtifactSetDigest     string
	LineageDigest         string
	ComponentSetDigest    string
	CustodyReportDigest   string
	AuditCheckpointDigest string
	Outcome               VerificationOutcome
	ReasonCode            VerificationReason
	VerifiedAt            time.Time
	ReportDigest          string
}

type AuthorizationRequest struct {
	SchemaVersion            string
	ContractVersion          string
	AuthorizationDigest      string
	IntentDigest             string
	Command                  Command
	CaseState                string
	CaseClassification       string
	CaseRevision             uint64
	RetainUntil              time.Time
	LegalHold                bool
	HoldReleasePending       bool
	CaseProvenanceDigest     string
	ArtifactSetDigest        *string
	VerificationReportDigest *string
	CurrentCustodyHead       CustodyHead
	ProgressDigest           *string
}

type Decision struct {
	SchemaVersion        string
	ContractVersion      string
	DecisionID           string
	DecisionDigest       string
	AuthorizationDigest  string
	IntentDigest         string
	Operation            Operation
	Case                 domain.CaseRef
	ActorID              string
	ActorRevision        uint64
	ArtifactSetDigest    *string
	PackageDigest        *string
	PolicyDigest         string
	ApprovalDigest       *string
	RevocationDigest     string
	ExpectedCaseRevision uint64
	ExpectedCustodyHead  CustodyHead
	Outcome              DecisionOutcome
	ReasonCode           DecisionReason
	IssuedAt             time.Time
	ExpiresAt            time.Time
	Revision             uint64
}

type ArtifactProgress struct {
	Ordinal                uint16
	ArtifactDigest         string
	IngestionReceiptDigest *string
	CustodyReceiptDigest   *string
}

type Progress struct {
	SchemaVersion                     string
	ContractVersion                   string
	OperationID                       string
	Case                              domain.CaseRef
	Operation                         Operation
	Phase                             Phase
	CommandDigest                     string
	IntentDigest                      string
	DecisionDigest                    *string
	RevocationDigest                  *string
	PackageDigest                     *string
	ManifestDigest                    *string
	SignatureDigest                   *string
	VerificationReportDigest          *string
	LifecycleReceiptDigest            *string
	AuthorizationCustodyReceiptDigest *string
	CompletionCustodyReceiptDigest    *string
	DispositionAttestationDigest      *string
	Artifacts                         []ArtifactProgress
	UpdatedAt                         time.Time
	Revision                          uint64
	ProgressDigest                    string
}

type DispositionOutcome string

const (
	DispositionRemoved       DispositionOutcome = "removed"
	DispositionAlreadyAbsent DispositionOutcome = "already_absent"
)

type DispositionObject struct {
	Ordinal               uint16
	ArtifactDigest        string
	EncryptedObjectDigest string
	KeyRevision           uint64
	Outcome               DispositionOutcome
	OutcomeDigest         string
}

type DispositionAttestation struct {
	SchemaVersion                     string
	ContractVersion                   string
	AttestationID                     string
	Case                              domain.CaseRef
	OperationID                       string
	ArtifactSetDigest                 string
	AuthorizationCustodyReceiptDigest string
	LifecycleReceiptDigest            string
	Mechanism                         string
	Objects                           []DispositionObject
	AttemptedAt                       time.Time
	CompletedAt                       time.Time
	AttestationDigest                 string
}

type Record struct {
	SchemaVersion                     string
	ContractVersion                   string
	OperationID                       string
	Case                              domain.CaseRef
	Operation                         Operation
	CommandDigest                     string
	IntentDigest                      string
	DecisionDigest                    string
	RevocationDigest                  string
	Artifacts                         []EvidenceReference
	ArtifactSetDigest                 *string
	PackageDigest                     *string
	ManifestDigest                    *string
	SignatureDigest                   *string
	VerificationReportDigest          *string
	LifecycleReceiptDigest            *string
	AuthorizationCustodyReceiptDigest *string
	CompletionCustodyReceiptDigest    *string
	DispositionAttestationDigest      *string
	AuditEventDigest                  string
	CompletedAt                       time.Time
	PreviousProvenanceDigest          string
	ProvenanceDigest                  string
	RecordDigest                      string
}

type Receipt struct {
	SchemaVersion                  string
	ContractVersion                string
	RequestID                      string
	OperationID                    string
	Case                           domain.CaseRef
	Operation                      Operation
	IdempotencyDigest              string
	IntentDigest                   string
	DecisionDigest                 string
	RecordDigest                   string
	Artifacts                      []EvidenceReference
	ArtifactSetDigest              *string
	PackageDigest                  *string
	ManifestDigest                 *string
	SignatureDigest                *string
	VerificationReportDigest       *string
	LifecycleReceiptDigest         *string
	CompletionCustodyReceiptDigest *string
	DispositionAttestationDigest   *string
	AuditEventDigest               string
	ProvenanceDigest               string
	CreatedAt                      time.Time
	ReceiptDigest                  string
}

type Result struct {
	Receipt          Receipt
	ReleaseReference *string
	Imported         []EvidenceReference
	Replayed         bool
}
