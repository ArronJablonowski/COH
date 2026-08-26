package broker

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/ArronJablonowski/COH/internal/policy/approvalfingerprint"
)

const preDispatchSchemaVersion = "coh.pre-dispatch/v1"

type preDispatchPolicyEvaluator interface {
	Evaluate(context.Context, policy.Request, policy.BundleAuthority) (policy.Decision, error)
}

type preDispatchApprovalConsumer interface {
	consumeApproval(context.Context, approvalTransitionCommand) (approvalResult, error)
}

type preDispatchAuditAppender interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

// signedROEVerifier is intentionally broker-private until COH-E19 freezes the
// ROE document contract. Implementations resolve and cryptographically verify
// the exact expected digest; raw ROE bytes never enter the gate result.
type signedROEVerifier interface {
	verifySignedROE(context.Context, signedROEExpectation) (verifiedROEProof, error)
}

type signedROEExpectation struct {
	Digest         string
	OrganizationID string
	TenantID       string
	CaseID         string
	VerifyAt       string
}

type verifiedROEProof struct {
	Digest             string
	OrganizationID     string
	TenantID           string
	CaseID             string
	Revision           uint64
	ValidFrom          string
	ValidUntil         string
	VerifiedAt         string
	SignerKeyID        string
	SignerKeyRevision  uint64
	SignatureAlgorithm string
	SignerActive       bool
}

type preDispatchCommand struct {
	SignedManifest []byte
	ManifestSigner actionmanifest.SignerAuthority
	EvaluationID   string
	PolicyActor    policy.ActorAuthority
	Runtime        policy.RuntimeAuthority
	PolicySigner   policy.BundleAuthority
	Approval       approvalTransitionCommand
	Fingerprint    approvalfingerprint.Fingerprint
	IntentDecision policy.Decision
}

// preDispatchAuthority is an unexported, non-serializable capability. Future
// dispatch composition must receive this value directly from authorize.
type preDispatchAuthority struct {
	Manifest            actionmanifest.VerifiedEnvelope
	PreDispatchDecision policy.Decision
	Approval            lifecycle.Record
	ROE                 *verifiedROEProof
	AuditEventID        string
}

type preDispatchGate struct {
	policy   preDispatchPolicyEvaluator
	approval preDispatchApprovalConsumer
	roe      signedROEVerifier
	audit    preDispatchAuditAppender
	clock    approvalClock
}

func newPreDispatchGate(evaluator preDispatchPolicyEvaluator, approval preDispatchApprovalConsumer,
	roe signedROEVerifier, audit preDispatchAuditAppender, clock approvalClock) (*preDispatchGate, error) {
	if evaluator == nil || approval == nil || roe == nil || audit == nil || clock == nil {
		return nil, lifecycle.NewError(lifecycle.InvalidInput, "predispatch_dependencies")
	}
	return &preDispatchGate{policy: evaluator, approval: approval, roe: roe, audit: audit, clock: clock}, nil
}

func (gate *preDispatchGate) now() time.Time {
	if gate == nil || gate.clock == nil {
		return time.Time{}
	}
	return gate.clock.Now().UTC()
}
