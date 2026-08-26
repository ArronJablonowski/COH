package broker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/ArronJablonowski/COH/internal/policy/approvalfingerprint"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	manifestID        = "0198d6c4-dddd-7ddd-8ddd-dddddddddddd"
	workflowTaskID    = "0198d6c4-eeee-7eee-8eee-eeeeeeeeeeee"
	bundleID          = "0198d6c4-f111-7111-8111-111111111111"
	intentEvalID      = "0198d6c4-f222-7222-8222-222222222222"
	predispatchEvalID = "0198d6c4-f333-7333-8333-333333333333"
)

type preDispatchFixture struct {
	gate        *preDispatchGate
	command     preDispatchCommand
	service     *approvalService
	policy      *gatePolicy
	roe         *gateROE
	audit       *gateAudit
	consumer    *gateApproval
	order       *[]string
	manifest    actionmanifest.Manifest
	verified    actionmanifest.VerifiedEnvelope
	signer      actionmanifest.SignerAuthority
	fingerprint approvalfingerprint.Fingerprint
}

func newPreDispatchFixture(t *testing.T, tier string) *preDispatchFixture {
	return newPreDispatchFixtureState(t, tier, true)
}

func newPreDispatchFixtureState(t *testing.T, tier string, completeT4 bool) *preDispatchFixture {
	t.Helper()
	order := &[]string{}
	manifest, signed, verified, signer := signedGateManifest(t, tier)
	clock := &fakeClock{now: testTime}
	fingerprintAudit := &gateFingerprintAudit{}
	fingerprintEngine, err := approvalfingerprint.New(fingerprintAudit, clock)
	if err != nil {
		t.Fatal(err)
	}
	intent := gateDecision(manifest, verified.ManifestDigest, intentEvalID, policy.IntentCreated,
		"intent.policy", 3, testTime.Format(timestampLayout))
	fingerprint, err := fingerprintEngine.Build(context.Background(), verified, signer, intent)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{records: make(map[string]workflow.MetadataRecord)}
	service, err := newApprovalServiceWithDependencies(store, approvalFingerprintEngine{engine: fingerprintEngine},
		&memoryAudit{}, clock, &sequenceReader{})
	if err != nil {
		t.Fatal(err)
	}
	request := approvalRequestCommand{ApprovalID: approvalID, IdempotencyKey: "gate-request", Requestor: requestor(),
		Principal: principal(requestor(), requestorPrincipalID), approvalProof: approvalProof{
			Fingerprint: fingerprint, Manifest: verified, Signer: signer, Decision: intent}}
	if _, err := service.requestApproval(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	grant := gateTransition("gate-grant-one", 1, approver(), verified, signer, fingerprint, intent)
	if _, err := service.grantApproval(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	revision := uint64(2)
	grants := []approvalGrantAuthority{grantAuthority(approver(), approverPrincipalID)}
	if tier == "T4" && completeT4 {
		second := gateTransition("gate-grant-two", 2, secondApprover(), verified, signer, fingerprint, intent)
		if _, err := service.grantApproval(context.Background(), second); err != nil {
			t.Fatal(err)
		}
		revision = 3
		grants = append(grants, grantAuthority(secondApprover(), secondPrincipalID))
	}
	policyEvaluator := &gatePolicy{order: order, now: testTime}
	roe := &gateROE{order: order}
	audit := &gateAudit{order: order}
	consumer := &gateApproval{service: service, order: order}
	gate, err := newPreDispatchGate(policyEvaluator, consumer, roe, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	command := preDispatchCommand{SignedManifest: signed, ManifestSigner: signer, EvaluationID: predispatchEvalID,
		PolicyActor: requestor(), Runtime: validGateRuntime(), PolicySigner: gatePolicySigner(),
		Approval: approvalTransitionCommand{ApprovalID: approvalID, IdempotencyKey: "gate-consume",
			ExpectedRevision: revision, Case: caseRef(), Actor: owner(), GrantAuthorities: grants,
			ReasonCode: "approval_consumed"}, Fingerprint: fingerprint, IntentDecision: intent}
	return &preDispatchFixture{gate: gate, command: command, service: service, policy: policyEvaluator,
		roe: roe, audit: audit, consumer: consumer, order: order, manifest: manifest, verified: verified, signer: signer,
		fingerprint: fingerprint}
}

func signedGateManifest(t *testing.T, tier string) (actionmanifest.Manifest, []byte,
	actionmanifest.VerifiedEnvelope, actionmanifest.SignerAuthority) {
	t.Helper()
	rollback, roe, watch := gateDigest("8"), gateDigest("9"), secondApproverID
	manifest := actionmanifest.Manifest{SchemaVersion: actionmanifest.ManifestSchemaVersion,
		ContractVersion: actionmanifest.ContractVersion, ManifestID: manifestID, WorkflowTaskID: workflowTaskID,
		OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID, RequestorActorID: requestorID,
		ActionOwnerActorID: ownerID, ActionType: "connector.execute", Operation: "execute", ActionTier: tier,
		TargetDigests: []string{gateDigest("1")}, ExclusionDigests: []string{}, ArgumentsDigest: gateDigest("2"),
		Tool:          actionmanifest.Tool{Name: "gate.tool", Version: "1.0.0", Digest: gateDigest("3")},
		PayloadDigest: gateDigest("4"), PolicyDigest: gateDigest("5"), PolicyRevision: 7,
		CredentialClass: "none", ExecutionZone: "isolated.native", IsolationProfileDigest: gateDigest("6"),
		ValidFrom: testTime.Add(-1e9).Format(timestampLayout), ValidUntil: testTime.Add(60e9).Format(timestampLayout),
		ManifestNonce:   base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32))),
		MaximumUseCount: 1, RollbackDigest: &rollback}
	if tier == "T4" {
		manifest.ROEDigest, manifest.SafetyWatchActorID = &roe, &watch
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := actionmanifest.Decode(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("m", ed25519.SeedSize)))
	authority := actionmanifest.SignerAuthority{ActorID: requestorID, KeyID: "requestor.primary", KeyRevision: 4,
		Active: true, PublicKey: privateKey.Public().(ed25519.PublicKey)}
	message := append([]byte(actionmanifest.SignatureDomain), validated.CanonicalBytes()...)
	envelope := actionmanifest.Envelope{SchemaVersion: actionmanifest.EnvelopeSchemaVersion,
		ContractVersion: actionmanifest.ContractVersion, Manifest: validated.Value(), ManifestDigest: validated.Digest,
		SignerActorID: authority.ActorID, SignerKeyRevision: authority.KeyRevision, KeyID: authority.KeyID,
		SignatureAlgorithm: "ed25519", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}
	signed, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := actionmanifest.Verify(context.Background(), signed, authority)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, signed, verified, authority
}

func gateTransition(key string, revision uint64, actor policy.ActorAuthority, manifest actionmanifest.VerifiedEnvelope,
	signer actionmanifest.SignerAuthority, fingerprint approvalfingerprint.Fingerprint,
	decision policy.Decision) approvalTransitionCommand {
	principalAuthority := principal(actor, principalIDForActor(actor.ActorID))
	return approvalTransitionCommand{ApprovalID: approvalID, IdempotencyKey: key, ExpectedRevision: revision,
		Case: caseRef(), Actor: actor, Principal: &principalAuthority, ReasonCode: "approval_granted",
		approvalProof: &approvalProof{Fingerprint: fingerprint, Manifest: manifest, Signer: signer, Decision: decision}}
}

func gateDecision(manifest actionmanifest.Manifest, manifestDigest, evaluationID string, phase policy.Phase,
	keyID string, keyRevision uint64, evaluatedAt string) policy.Decision {
	decision := policy.Decision{SchemaVersion: policy.SchemaVersion, ContractVersion: policy.ContractVersion,
		EvaluationID: evaluationID, InputDigest: gateDigest("a"), Outcome: "allowed", ReasonCode: "policy_allowed",
		Phase: phase, ManifestDigest: manifestDigest, PolicyDigest: manifest.PolicyDigest,
		PolicyRevision: manifest.PolicyRevision, BundleID: bundleID, SignerKeyID: keyID,
		SignerKeyRevision: keyRevision, ActorID: requestorID, ActorRevision: requestor().Revision,
		ApprovalRequired: true, EvaluatedAt: evaluatedAt, AuditOrganizationID: organizationID,
		AuditTenantID: tenantID, AuditCaseID: caseID}
	finalized, err := policy.FinalizeDecision(decision)
	if err != nil {
		panic(err)
	}
	return finalized
}

func validGateRuntime() policy.RuntimeAuthority {
	return policy.RuntimeAuthority{DataRoute: "direct", ValidatorState: "qualified", ToolRegistered: true,
		TargetsAuthorized: true, TenantAuthorized: true, DataRouteAuthorized: true, CapabilityFieldsKnown: true}
}

func gatePolicySigner() policy.BundleAuthority {
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", ed25519.SeedSize)))
	return policy.BundleAuthority{KeyID: "predispatch.policy", KeyRevision: 9, Algorithm: "ed25519", Active: true,
		PublicKey: privateKey.Public().(ed25519.PublicKey)}
}

func gateDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func caseRef() domain.CaseRef {
	return domain.CaseRef{OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID}
}

type gatePolicy struct {
	order  *[]string
	now    time.Time
	err    error
	mutate func(*policy.Decision)
}

func (evaluator *gatePolicy) Evaluate(ctx context.Context, request policy.Request,
	signer policy.BundleAuthority) (policy.Decision, error) {
	*evaluator.order = append(*evaluator.order, "policy")
	if err := ctx.Err(); err != nil {
		return policy.Decision{}, err
	}
	if evaluator.err != nil {
		return policy.Decision{}, evaluator.err
	}
	decision := gateDecision(request.Manifest.Manifest(), request.Manifest.ManifestDigest, request.EvaluationID,
		request.Phase, signer.KeyID, signer.KeyRevision, evaluator.now.Format(timestampLayout))
	decision.ActorRevision = request.Actor.Revision
	if evaluator.mutate != nil {
		evaluator.mutate(&decision)
	}
	decision.DecisionDigest = ""
	decision, _ = policy.FinalizeDecision(decision)
	return decision, nil
}

type gateROE struct {
	order  *[]string
	fail   bool
	mutate func(*verifiedROEProof)
}

func (verifier *gateROE) verifySignedROE(_ context.Context, expected signedROEExpectation) (verifiedROEProof, error) {
	*verifier.order = append(*verifier.order, "roe")
	if verifier.fail {
		return verifiedROEProof{}, errors.New("invalid ROE")
	}
	proof := verifiedROEProof{Digest: expected.Digest, OrganizationID: expected.OrganizationID,
		TenantID: expected.TenantID, CaseID: expected.CaseID, Revision: 2,
		ValidFrom: testTime.Add(-1e9).Format(timestampLayout), ValidUntil: testTime.Add(60e9).Format(timestampLayout),
		VerifiedAt: expected.VerifyAt, SignerKeyID: "roe.primary", SignerKeyRevision: 3,
		SignatureAlgorithm: "ed25519", SignerActive: true}
	if verifier.mutate != nil {
		verifier.mutate(&proof)
	}
	return proof, nil
}

type gateApproval struct {
	service *approvalService
	order   *[]string
	cancel  context.CancelFunc
}

func (consumer *gateApproval) consumeApproval(ctx context.Context, command approvalTransitionCommand) (approvalResult, error) {
	*consumer.order = append(*consumer.order, "approval")
	result, err := consumer.service.consumeApproval(ctx, command)
	if consumer.cancel != nil {
		consumer.cancel()
	}
	return result, err
}

type gateAudit struct {
	order  *[]string
	events []tamperaudit.Event
	fail   bool
}

func (audit *gateAudit) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	*audit.order = append(*audit.order, "audit")
	if audit.fail {
		return errors.New("audit down")
	}
	audit.events = append(audit.events, event)
	return nil
}

type gateFingerprintAudit struct{}

func (*gateFingerprintAudit) AppendApprovalFingerprintEvent(context.Context, approvalfingerprint.AuditEvent) error {
	return nil
}
