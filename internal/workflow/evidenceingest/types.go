// Package evidenceingest owns immutable, encrypted, case-scoped evidence ingestion.
package evidenceingest

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

const (
	CommandSchemaVersion         = "coh.evidence-ingest-command/v1"
	AuthorizationSchemaVersion   = "coh.evidence-ingest-authorization/v1"
	DecisionSchemaVersion        = "coh.evidence-ingest-decision/v1"
	ManifestSchemaVersion        = "coh.artifact-manifest/v1"
	EncryptedObjectSchemaVersion = "coh.encrypted-object/v1"
	ReceiptSchemaVersion         = "coh.evidence-ingest-receipt/v1"
	ContractVersion              = "1.0.0"
	EncryptionFormatVersion      = "coh.encrypted-cas/aes-256-gcm-chunked/v1"
)

type Status string

const (
	Staged    Status = "staged"
	Verified  Status = "verified"
	Published Status = "published"
)

type TransportMode string

const (
	InProcess TransportMode = "in_process"
	MTLS      TransportMode = "mtls"
)

type SourceKind string

const (
	UploadSource    SourceKind = "upload"
	ConnectorSource SourceKind = "connector"
	QuerySource     SourceKind = "query"
	ToolSource      SourceKind = "tool"
	ModelSource     SourceKind = "model"
	DerivedSource   SourceKind = "derived"
	ImportSource    SourceKind = "import"
)

type ComponentKind string

const (
	ToolComponent  ComponentKind = "tool"
	QueryComponent ComponentKind = "query"
	ModelComponent ComponentKind = "model"
)

type TimePrecision string

const (
	NanosecondPrecision  TimePrecision = "nanosecond"
	MicrosecondPrecision TimePrecision = "microsecond"
	MillisecondPrecision TimePrecision = "millisecond"
	SecondPrecision      TimePrecision = "second"
	MinutePrecision      TimePrecision = "minute"
	DayPrecision         TimePrecision = "day"
	UnknownPrecision     TimePrecision = "unknown"
)

type TransportContext struct {
	Mode                 TransportMode
	PeerIdentityDigest   string
	ChannelBindingDigest string
}

type ObservedTime struct {
	Value                 time.Time
	OriginalOffsetMinutes int16
	Precision             TimePrecision
	UncertaintyNanos      uint64
}

type SourceTimeRange struct {
	Start ObservedTime
	End   ObservedTime
}

type SourceInput struct {
	Kind                    SourceKind
	Identity                string
	IdentityDigest          string
	CollectionMethod        string
	CollectionMethodVersion string
	CollectedAt             time.Time
	SourceTime              *ObservedTime
	SourceRange             *SourceTimeRange
}

type ComponentVersion struct {
	Kind    ComponentKind
	Name    string
	Version string
	Digest  string
}

type Command struct {
	SchemaVersion         string
	ContractVersion       string
	RequestID             string
	IdempotencyKey        string
	Case                  domain.CaseRef
	ActorID               string
	ActorRevision         uint64
	ExpectedDigest        string
	ExpectedLength        int64
	MediaType             string
	Classification        string
	Source                SourceInput
	ParentArtifacts       []domain.ArtifactRef
	ParentManifestDigests []string
	Components            []ComponentVersion
	KeyProfile            string
	KeyProfileDigest      string
	PolicyDigest          string
	Transport             TransportContext
	Deadline              time.Time
}

type AuthorizationRequest struct {
	SchemaVersion        string
	ContractVersion      string
	AuthorizationDigest  string
	IntentDigest         string
	Command              Command
	CaseRevision         uint64
	CaseState            string
	CaseClassification   string
	CaseProvenanceDigest string
}

type Decision struct {
	SchemaVersion       string
	ContractVersion     string
	DecisionID          string
	DecisionDigest      string
	AuthorizationDigest string
	IntentDigest        string
	Case                domain.CaseRef
	ActorID             string
	ActorRevision       uint64
	ArtifactDigest      string
	ArtifactLength      int64
	PolicyDigest        string
	KeyProfileDigest    string
	TransportDigest     string
	RevocationDigest    string
	Outcome             string
	ReasonCode          string
	IssuedAt            time.Time
	ExpiresAt           time.Time
	Revision            uint64
}

type ArtifactManifest struct {
	SchemaVersion            string
	ContractVersion          string
	ManifestID               string
	Case                     domain.CaseRef
	Artifact                 domain.ArtifactRef
	Source                   SourceInput
	ParentArtifacts          []domain.ArtifactRef
	ParentManifestDigests    []string
	Components               []ComponentVersion
	ActorID                  string
	ActorRevision            uint64
	PolicyDigest             string
	AuthorizationDigest      string
	DecisionDigest           string
	RevocationDigest         string
	TransportDigest          string
	EncryptionContextDigest  string
	AuditEventDigest         string
	PreviousProvenanceDigest *string
	ProvenanceDigest         string
	CreatedAt                time.Time
	Revision                 uint64
}

type EncryptedObject struct {
	SchemaVersion           string
	ContractVersion         string
	Status                  Status
	Case                    domain.CaseRef
	PlaintextDigest         string
	PlaintextLength         int64
	CiphertextDigest        string
	CiphertextLength        int64
	MediaType               string
	Classification          string
	EncryptionFormat        string
	ChunkSize               uint32
	ChunkCount              uint64
	KeyReference            string
	KeyRevision             uint64
	KeyAlgorithm            string
	WrappedKeyDigest        string
	EncryptionContextDigest string
	LocatorDigest           string
	CreatedAt               time.Time
}

// PublishedObject is the non-sensitive SQL-safe identity of one encrypted CAS
// object. Key references and wrapped-key material remain only in the encrypted
// object header owned by the CAS adapter.
type PublishedObject struct {
	Case                    domain.CaseRef
	PlaintextDigest         string
	PlaintextLength         int64
	CiphertextDigest        string
	CiphertextLength        int64
	EncryptionFormat        string
	EncryptionContextDigest string
	LocatorDigest           string
}

type Receipt struct {
	SchemaVersion            string
	ContractVersion          string
	RequestID                string
	Case                     domain.CaseRef
	ActorID                  string
	ActorRevision            uint64
	IntentDigest             string
	IdempotencyDigest        string
	AuthorizationDigest      string
	DecisionDigest           string
	RevocationDigest         string
	TransportDigest          string
	Artifact                 domain.ArtifactRef
	Manifest                 domain.ArtifactRef
	EncryptedArtifact        PublishedObject
	EncryptedManifest        PublishedObject
	ManifestProvenanceDigest string
	AuditEventDigest         string
	CreatedAt                time.Time
	ReceiptDigest            string
}

type Result struct {
	Artifact domain.ArtifactRef
	Manifest domain.ArtifactRef
	Receipt  Receipt
	Replayed bool
}

type StageRequest struct {
	Case                    domain.CaseRef
	ExpectedDigest          string
	ExpectedLength          int64
	MediaType               string
	Classification          string
	KeyProfile              string
	KeyProfileDigest        string
	EncryptionContextDigest string
	Deadline                time.Time
}

// CaseSnapshot is the minimum current lifecycle state ingestion may authorize
// against. It intentionally excludes lifecycle mutation methods and records.
type CaseSnapshot struct {
	Case             domain.CaseRef
	Revision         uint64
	State            string
	Classification   string
	ProvenanceDigest string
}

type Authority interface {
	AuthorizeIngestion(context.Context, AuthorizationRequest) (Decision, error)
}

// Source is a cancellation-aware, forward-only evidence stream. Implementers
// must return promptly when ctx is done and must not support seek or replay.
type Source interface {
	ReadContext(context.Context, []byte) (int, error)
}

type TransportVerifier interface {
	VerifyTransport(context.Context, TransportContext) error
}

type CaseStore interface {
	LoadCase(context.Context, domain.CaseRef) (CaseSnapshot, bool, error)
}

type EncryptedCAS interface {
	Stage(context.Context, StageRequest, Source) (EncryptedObject, error)
	Verify(context.Context, EncryptedObject) error
	Publish(context.Context, EncryptedObject) (EncryptedObject, bool, error)
	Resolve(context.Context, PublishedObject) (EncryptedObject, error)
	Abandon(context.Context, EncryptedObject) error
}

type ManifestStore interface {
	Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error)
	Commit(context.Context, string, string, Receipt) (Receipt, bool, error)
}

type Auditor interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type Clock interface{ Now() time.Time }
