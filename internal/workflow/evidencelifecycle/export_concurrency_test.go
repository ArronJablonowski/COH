package evidencelifecycle

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func TestExportServiceConcurrentExactReplayReturnsOneImmutableResult(t *testing.T) {
	rig := newExportRig(t)
	first, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil {
		t.Fatal(err)
	}
	ports := concurrentExportReplayPorts{
		now: lifecycleTestNow, receipt: first.Receipt, snapshot: rig.cases.snapshot,
		lifecycle: rig.cases.proof, evidence: rig.service.evidence.(exportEvidence).value,
		head: rig.custody.head, heads: cloneHeads(rig.custody.heads),
		custody: cloneCustodyProofs(rig.custody.recovered), packaged: rig.packages.value,
		manifest: rig.packages.manifest, signature: rig.packages.signature,
	}
	service, err := NewExportService(&ports, &ports, &ports, &ports, &ports, &ports, &ports, &ports,
		&ports, &ports, &ports, &ports, rig.service.signing)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	errorsFound := make(chan error, 32)
	var workers sync.WaitGroup
	for index := 0; index < cap(errorsFound); index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, executeErr := service.Execute(ctx, rig.command)
			if executeErr != nil || !result.Replayed || result.ReleaseReference == nil ||
				*result.ReleaseReference != *first.ReleaseReference ||
				result.Receipt.ReceiptDigest != first.Receipt.ReceiptDigest {
				errorsFound <- fmt.Errorf("result=%+v err=%v", result, executeErr)
			}
		}()
	}
	workers.Wait()
	close(errorsFound)
	for workerErr := range errorsFound {
		t.Error(workerErr)
	}
}

type concurrentExportReplayPorts struct {
	now       time.Time
	receipt   Receipt
	snapshot  CaseSnapshot
	lifecycle LifecycleProof
	evidence  VerifiedEvidenceSet
	head      CustodyHead
	heads     map[uint64]CustodyHead
	custody   map[string]CustodyProofSet
	packaged  QuarantinedPackage
	manifest  ExportManifest
	signature DetachedSignature
}

func cloneHeads(source map[uint64]CustodyHead) map[uint64]CustodyHead {
	result := make(map[uint64]CustodyHead, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneCustodyProofs(source map[string]CustodyProofSet) map[string]CustodyProofSet {
	result := make(map[string]CustodyProofSet, len(source))
	for key, value := range source {
		value.Proofs = append([]CustodyProof(nil), value.Proofs...)
		result[key] = value
	}
	return result
}

func (ports *concurrentExportReplayPorts) Now() time.Time { return ports.now }

func (ports *concurrentExportReplayPorts) Recover(context.Context, domain.CaseRef,
	string) (Receipt, bool, error) {
	return ports.receipt, true, nil
}
func (*concurrentExportReplayPorts) LoadProgress(context.Context, domain.CaseRef,
	string) (Progress, bool, error) {
	return Progress{}, false, nil
}
func (*concurrentExportReplayPorts) Advance(context.Context, string, string,
	Progress) (Progress, bool, error) {
	return Progress{}, false, fmt.Errorf("unexpected advance")
}
func (*concurrentExportReplayPorts) Commit(context.Context, string, string, Progress,
	Record, Receipt) (Receipt, bool, error) {
	return Receipt{}, false, fmt.Errorf("unexpected commit")
}

func (ports *concurrentExportReplayPorts) LoadCase(context.Context,
	domain.CaseRef) (CaseSnapshot, bool, error) {
	return ports.snapshot, true, nil
}
func (ports *concurrentExportReplayPorts) ResolveLifecycleReceipt(context.Context, domain.CaseRef,
	string) (LifecycleProof, bool, error) {
	return ports.lifecycle, true, nil
}
func (*concurrentExportReplayPorts) HasIncompleteHoldRelease(context.Context, domain.CaseRef) (bool, error) {
	return false, nil
}
func (*concurrentExportReplayPorts) ApplyCaseOperation(context.Context,
	LifecycleRequest) (LifecycleProof, error) {
	return LifecycleProof{}, fmt.Errorf("unexpected lifecycle mutation")
}

func (ports *concurrentExportReplayPorts) ResolveEvidenceSet(context.Context, domain.CaseRef,
	string) (VerifiedEvidenceSet, error) {
	return ports.evidence, nil
}
func (*concurrentExportReplayPorts) VerifyRedactionReceipts(context.Context, domain.CaseRef,
	VerifiedEvidenceSet) ([]RedactionProof, error) {
	return []RedactionProof{}, nil
}

func (ports *concurrentExportReplayPorts) LoadCustodyHead(context.Context, domain.CaseRef) (CustodyHead, error) {
	return ports.head, nil
}
func (ports *concurrentExportReplayPorts) VerifyLifecycle(_ context.Context, scope domain.CaseRef,
	from, to uint64) (CustodyVerification, error) {
	head, found := ports.heads[to]
	if !found {
		return CustodyVerification{}, fmt.Errorf("missing custody head")
	}
	return CustodyVerification{FromSequence: from, ToSequence: to, Head: head,
		CheckpointID: lifecycleUUID("concurrent-checkpoint"), CheckpointDigest: lifecycleDigest("concurrent-checkpoint"),
		CheckpointSequence: to, CheckpointSigningKeyRevision: 2,
		CheckpointProofDigest: lifecycleDigest("concurrent-proof"),
		ReportDigest:          lifecycleDigest("concurrent-report")}, nil
}
func (*concurrentExportReplayPorts) RecordLifecycle(context.Context,
	CustodyRequest) (CustodyProofSet, error) {
	return CustodyProofSet{}, fmt.Errorf("unexpected custody mutation")
}
func (ports *concurrentExportReplayPorts) RecoverLifecycle(_ context.Context, _ domain.CaseRef,
	digest string) (CustodyProofSet, bool, error) {
	value, found := ports.custody[digest]
	return value, found, nil
}

func (ports *concurrentExportReplayPorts) AuthorizeEvidenceLifecycle(_ context.Context,
	request AuthorizationRequest) (Decision, error) {
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID:          lifecycleUUID("concurrent-decision-" + request.AuthorizationDigest),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Operation: Export, Case: request.Command.Case, ActorID: request.Command.ActorID,
		ActorRevision: request.Command.ActorRevision, ArtifactSetDigest: request.ArtifactSetDigest,
		PolicyDigest: request.Command.PolicyDigest, ApprovalDigest: request.Command.ApprovalDigest,
		RevocationDigest: lifecycleDigest("concurrent-revocation"), ExpectedCaseRevision: request.CaseRevision,
		ExpectedCustodyHead: request.CurrentCustodyHead, Outcome: Allow, ReasonCode: ReasonAuthorized,
		IssuedAt: ports.now, ExpiresAt: ports.now.Add(30 * time.Minute), Revision: 1}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value, nil
}

func (*concurrentExportReplayPorts) BuildPackage(context.Context,
	PackageBuildRequest) (QuarantinedPackage, error) {
	return QuarantinedPackage{}, fmt.Errorf("unexpected package build")
}
func (ports *concurrentExportReplayPorts) RecoverPackage(context.Context, domain.CaseRef,
	string) (QuarantinedPackage, bool, error) {
	return ports.packaged, true, nil
}
func (ports *concurrentExportReplayPorts) RecoverPackageProof(context.Context, QuarantinedPackage,
	PackageLimits) (ExportManifest, DetachedSignature, error) {
	return ports.manifest, ports.signature, nil
}
func (*concurrentExportReplayPorts) VerifyPackage(context.Context, QuarantinedPackage, PackageLimits) error {
	return nil
}
func (*concurrentExportReplayPorts) SignManifest(context.Context, SignRequest) (DetachedSignature, error) {
	return DetachedSignature{}, fmt.Errorf("unexpected signing")
}
func (*concurrentExportReplayPorts) VerifyDetachedSignature(context.Context, VerifySignatureRequest) error {
	return nil
}
func (*concurrentExportReplayPorts) AppendLifecycleEvent(context.Context, tamperaudit.Event) error {
	return fmt.Errorf("unexpected audit append")
}
func (*concurrentExportReplayPorts) VerifyLifecycleEvent(context.Context, domain.CaseRef, string, string) error {
	return nil
}
