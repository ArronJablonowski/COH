package evidencelifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestHoldServicePlacesAndReleasesUsingExactLifecycleAndCustodyReceipts(t *testing.T) {
	for _, operation := range []Operation{PlaceHold, ReleaseHold} {
		t.Run(string(operation), func(t *testing.T) {
			rig := newHoldRig(t, operation)
			result, err := rig.service.Execute(t.Context(), rig.command)
			if err != nil {
				t.Fatal(err)
			}
			if result.Replayed || len(result.Imported) != 0 || ValidateReceipt(result.Receipt) != nil ||
				rig.cases.snapshot.LegalHold != (operation == PlaceHold) ||
				rig.authority.request.RetainUntil != lifecycleTestNow.Add(24*time.Hour) ||
				rig.authority.request.ArtifactSetDigest == nil ||
				*rig.authority.request.ArtifactSetDigest != *rig.command.ArtifactSetDigest {
				t.Fatalf("result=%+v case=%+v", result, rig.cases.snapshot)
			}
			want := []string{"recover", "progress.load", "case.load", "case.hold", "evidence", "custody.head",
				"authority", "store.planned", "case." + string(operation), "case.resolve", "store.case_recorded",
				"custody.completed", "custody.verify", "store.custodied", "audit.append", "audit.verify", "store.commit"}
			if !reflect.DeepEqual(rig.calls, want) {
				t.Fatalf("calls=%v\nwant=%v", rig.calls, want)
			}
		})
	}
}

func TestHoldServiceResumesTransitionAndCustodyWithoutRepeatingCaseMutation(t *testing.T) {
	for _, operation := range []Operation{PlaceHold, ReleaseHold} {
		t.Run(string(operation), func(t *testing.T) {
			rig := newHoldRig(t, operation)
			rig.custody.failPhase = Completed
			if result, err := rig.service.Execute(t.Context(), rig.command); err == nil || len(result.Imported) != 0 ||
				rig.store.progress.Phase != CaseRecorded {
				t.Fatalf("first result=%+v err=%v phase=%s", result, err, rig.store.progress.Phase)
			}
			rig.custody.failPhase, rig.calls = "", nil
			result, err := rig.service.Execute(t.Context(), rig.command)
			if err != nil || ValidateReceipt(result.Receipt) != nil ||
				containsCall(rig.calls, "case."+string(operation)) || !containsCall(rig.calls, "case.resolve") {
				t.Fatalf("recovery calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestHoldServiceRecoversCustodyBeforeFinalCommit(t *testing.T) {
	rig := newHoldRig(t, ReleaseHold)
	rig.auditor.appendErr = errors.New("audit unavailable")
	if _, err := rig.service.Execute(t.Context(), rig.command); err == nil || rig.store.progress.Phase != Custodied {
		t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
	}
	rig.auditor.appendErr, rig.calls = nil, nil
	result, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil || ValidateReceipt(result.Receipt) != nil || !containsCall(rig.calls, "custody.recover") ||
		containsCall(rig.calls, "custody.completed") || containsCall(rig.calls, "case.release_hold") {
		t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
	}
}

func TestHoldServiceExactReplayReauthorizesAndVerifiesProofs(t *testing.T) {
	rig := newHoldRig(t, PlaceHold)
	first, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil {
		t.Fatal(err)
	}
	rig.calls = nil
	second, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil || !second.Replayed || second.Receipt.ReceiptDigest != first.Receipt.ReceiptDigest ||
		containsCall(rig.calls, "case.place_hold") || containsCall(rig.calls, "custody.completed") {
		t.Fatalf("calls=%v result=%+v err=%v", rig.calls, second, err)
	}
}

func TestHoldServiceDeniesChangedReplayAndStaleScope(t *testing.T) {
	rig := newHoldRig(t, PlaceHold)
	if _, err := rig.service.Execute(t.Context(), rig.command); err != nil {
		t.Fatal(err)
	}
	rig.calls = nil
	changed := rig.command
	changed.ReasonDigest = pointerDigest("changed-reason")
	result, err := rig.service.Execute(t.Context(), changed)
	if CodeOf(err) != Denied || Reason(err) != string(ReasonChangedReplay) ||
		result.Receipt.ReceiptDigest != "" || containsCall(rig.calls, "case.place_hold") {
		t.Fatalf("changed replay calls=%v result=%+v err=%v", rig.calls, result, err)
	}

	stale := newHoldRig(t, ReleaseHold)
	stale.command.ExpectedCustodyHead.ChainHash = lifecycleDigest("stale-head")
	result, err = stale.service.Execute(t.Context(), stale.command)
	if CodeOf(err) != Conflict || result.Receipt.ReceiptDigest != "" ||
		containsCall(stale.calls, "authority") || containsCall(stale.calls, "case.release_hold") {
		t.Fatalf("stale scope calls=%v result=%+v err=%v", stale.calls, result, err)
	}
}

func TestHoldServiceFailsClosedBeforeConsequentialSuccess(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*holdRig)
		absent string
	}{
		{"authority", func(rig *holdRig) { rig.authority.err = errors.New("authority unavailable") }, "case.place_hold"},
		{"case transition", func(rig *holdRig) { rig.lifecycle.err = errors.New("case unavailable") }, "custody.completed"},
		{"custody", func(rig *holdRig) { rig.custody.failPhase = Completed }, "store.commit"},
		{"audit", func(rig *holdRig) { rig.auditor.appendErr = errors.New("audit unavailable") }, "store.commit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newHoldRig(t, PlaceHold)
			test.mutate(rig)
			result, err := rig.service.Execute(t.Context(), rig.command)
			if err == nil || result.Receipt.ReceiptDigest != "" || containsCall(rig.calls, test.absent) {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

type holdRig struct {
	service   *HoldService
	command   Command
	calls     []string
	cases     *exportCases
	lifecycle *holdLifecycle
	authority *holdAuthority
	custody   *exportCustody
	auditor   *exportAuditor
	store     *holdStore
}

func newHoldRig(t *testing.T, operation Operation) *holdRig {
	t.Helper()
	rig := &holdRig{}
	now := lifecycleTestNow
	manifest := validExportManifest(t)
	command := validLifecycleCommand(operation)
	command.ArtifactSetDigest = &manifest.ArtifactSetDigest
	last := now.Add(-time.Minute)
	command.ExpectedCustodyHead = CustodyHead{Case: command.Case, Sequence: 2,
		ChainHash: lifecycleDigest("hold-head"), LastRecordAt: &last}
	evidence := VerifiedEvidenceSet{Case: command.Case, Artifacts: manifest.Artifacts, Components: manifest.Components,
		ArtifactSetDigest: manifest.ArtifactSetDigest, LineageDigest: lifecycleDigest("lineage")}
	evidence.ComponentSetDigest, _ = ComponentSetBindingDigest(evidence.Components)
	rig.cases = &exportCases{calls: &rig.calls, snapshot: CaseSnapshot{Case: command.Case, State: "open",
		Classification: "restricted", Revision: command.ExpectedCaseRevision, RetainUntil: now.Add(24 * time.Hour),
		LegalHold: operation == ReleaseHold, ProvenanceDigest: lifecycleDigest("case-provenance")}}
	rig.authority = &holdAuthority{calls: &rig.calls, now: now}
	rig.lifecycle = &holdLifecycle{calls: &rig.calls, cases: rig.cases}
	rig.custody = &exportCustody{calls: &rig.calls, head: command.ExpectedCustodyHead, now: now}
	rig.auditor = &exportAuditor{calls: &rig.calls}
	rig.store = &holdStore{calls: &rig.calls, cases: rig.cases}
	service, err := NewHoldService(rig.authority, rig.cases, rig.lifecycle,
		exportEvidence{calls: &rig.calls, value: evidence}, rig.custody, rig.store, rig.auditor, exportClock{now})
	if err != nil {
		t.Fatal(err)
	}
	rig.service, rig.command = service, command
	return rig
}

type holdAuthority struct {
	calls   *[]string
	now     time.Time
	err     error
	request AuthorizationRequest
}

func (stub *holdAuthority) AuthorizeEvidenceLifecycle(_ context.Context,
	request AuthorizationRequest) (Decision, error) {
	*stub.calls = append(*stub.calls, "authority")
	stub.request = request
	if stub.err != nil {
		return Decision{}, stub.err
	}
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID:          lifecycleUUID("hold-decision-" + request.AuthorizationDigest),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Operation: request.Command.Operation, Case: request.Command.Case, ActorID: request.Command.ActorID,
		ActorRevision: request.Command.ActorRevision, ArtifactSetDigest: request.ArtifactSetDigest,
		PolicyDigest: request.Command.PolicyDigest, RevocationDigest: lifecycleDigest("hold-revocation"),
		ExpectedCaseRevision: request.CaseRevision, ExpectedCustodyHead: request.CurrentCustodyHead,
		Outcome: Allow, ReasonCode: ReasonAuthorized, IssuedAt: stub.now,
		ExpiresAt: stub.now.Add(30 * time.Minute), Revision: 1}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value, nil
}

type holdLifecycle struct {
	calls *[]string
	cases *exportCases
	err   error
}

func (stub *holdLifecycle) ApplyCaseOperation(_ context.Context, request LifecycleRequest) (LifecycleProof, error) {
	*stub.calls = append(*stub.calls, "case."+string(request.Operation))
	if stub.err != nil {
		return LifecycleProof{}, stub.err
	}
	hold := request.Operation == PlaceHold
	stub.cases.snapshot.Revision++
	stub.cases.snapshot.LegalHold = hold
	stub.cases.snapshot.ProvenanceDigest = lifecycleDigest("case-provenance-" + string(request.Operation))
	stub.cases.pending = request.Operation == ReleaseHold
	proof := LifecycleProof{Operation: request.Operation, Case: request.Case, Revision: stub.cases.snapshot.Revision,
		LegalHold: hold, ReceiptDigest: lifecycleDigest("lifecycle-" + string(request.Operation)),
		ProvenanceDigest: stub.cases.snapshot.ProvenanceDigest}
	stub.cases.proof = proof
	return proof, nil
}

type holdStore struct {
	calls    *[]string
	cases    *exportCases
	progress Progress
	receipt  Receipt
}

func (stub *holdStore) Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error) {
	*stub.calls = append(*stub.calls, "recover")
	return stub.receipt, stub.receipt.ReceiptDigest != "", nil
}
func (stub *holdStore) LoadProgress(context.Context, domain.CaseRef, string) (Progress, bool, error) {
	*stub.calls = append(*stub.calls, "progress.load")
	return stub.progress, stub.progress.ProgressDigest != "", nil
}
func (stub *holdStore) Advance(_ context.Context, _, _ string, value Progress) (Progress, bool, error) {
	*stub.calls = append(*stub.calls, "store."+string(value.Phase))
	if ValidateProgress(value) != nil {
		return Progress{}, false, errors.New("invalid progress")
	}
	stub.progress = value
	return value, false, nil
}
func (stub *holdStore) Commit(_ context.Context, _, _ string, progress Progress, record Record,
	receipt Receipt) (Receipt, bool, error) {
	*stub.calls = append(*stub.calls, "store.commit")
	if ValidateProgress(progress) != nil || ValidateRecord(record) != nil || ValidateReceipt(receipt) != nil {
		return Receipt{}, false, errors.New("invalid commit")
	}
	stub.progress, stub.receipt, stub.cases.pending = progress, receipt, false
	return receipt, false, nil
}
