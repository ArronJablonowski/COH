package redaction

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type Authority interface {
	AuthorizeRedaction(context.Context, AuthorizationRequest) (Decision, error)
}

type ApprovalStore interface {
	AuthorizeUse(context.Context, ApprovalUseRequest) (ApprovalUseProof, bool, error)
	VerifyUse(context.Context, ApprovalUseProof) error
}

type CaseStore interface {
	LoadCase(context.Context, domain.CaseRef) (CaseSnapshot, bool, error)
}

type PlanStore interface {
	ResolvePlan(context.Context, domain.CaseRef, string) (ApprovedPlan, bool, error)
	ResolveRule(context.Context, string) (RuleSet, bool, error)
}

type SourceResolver interface {
	ResolveSource(context.Context, domain.CaseRef, EvidenceReference) (VerifiedSource, error)
}

// DerivedSource is forward-only derived output. It must not support seek,
// replay, inspection, or access to the immutable source plaintext.
type DerivedSource interface {
	ReadContext(context.Context, []byte) (int, error)
}

type Transformer interface {
	Derive(context.Context, DerivationRequest) (Derivation, DerivedSource, error)
}

type Publisher interface {
	Publish(context.Context, PublicationRequest, DerivedSource) (PublishedEvidence, error)
}

type CustodyRecorder interface {
	LoadCustodyHead(context.Context, domain.CaseRef) (CustodyHead, error)
	RecordRedaction(context.Context, CustodyRequest) (CustodyProof, bool, error)
	VerifyRedaction(context.Context, CustodyProof) error
}

type Store interface {
	Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error)
	LoadProgress(context.Context, domain.CaseRef, string) (Progress, bool, error)
	Advance(context.Context, string, uint64, Progress) (Progress, bool, error)
	Commit(context.Context, string, string, Record, Receipt) (Receipt, bool, error)
}

type Auditor interface {
	AppendRedactionEvent(context.Context, tamperaudit.Event) (AuditProof, error)
	VerifyRedactionEvent(context.Context, domain.CaseRef, string, string) (AuditProof, error)
}

type Clock interface{ Now() time.Time }
