package evidencelifecycle

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestDeleteServiceOrdersAuthorizationTombstoneDispositionCustodyAndCommit(t *testing.T) {
	rig := newDeleteRig(t)
	result, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || ValidateReceipt(result.Receipt) != nil || rig.cases.snapshot.State != "deleted" ||
		rig.disposer.calls != 1 {
		t.Fatalf("result=%+v case=%+v disposition_calls=%d", result, rig.cases.snapshot, rig.disposer.calls)
	}
	want := []string{"recover", "progress.load", "case.load", "case.hold", "evidence", "custody.head",
		"custody.verify", "authority", "store.planned", "custody.authorized", "custody.verify",
		"store.authorized", "case.delete", "case.resolve", "store.tombstoned", "case.load", "case.hold",
		"evidence", "dispose", "store.disposed", "custody.completed", "custody.verify", "store.custodied",
		"audit.append", "audit.verify", "store.commit"}
	if !reflect.DeepEqual(rig.calls, want) {
		t.Fatalf("calls=%v\nwant=%v", rig.calls, want)
	}
}

func TestDeleteServiceBlocksHoldRetentionAndIncompleteReleaseBeforeAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*deleteRig)
		reason DecisionReason
	}{
		{"legal hold", func(rig *deleteRig) { rig.cases.snapshot.LegalHold = true }, ReasonLegalHoldActive},
		{"retention", func(rig *deleteRig) { rig.cases.snapshot.RetainUntil = lifecycleTestNow.Add(time.Hour) }, ReasonRetentionActive},
		{"pending release", func(rig *deleteRig) { rig.cases.pending = true }, ReasonLegalHoldActive},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newDeleteRig(t)
			test.mutate(rig)
			result, err := rig.service.Execute(t.Context(), rig.command)
			if CodeOf(err) != Denied || Reason(err) != string(test.reason) || result.Receipt.ReceiptDigest != "" ||
				containsCall(rig.calls, "authority") || containsCall(rig.calls, "custody.authorized") ||
				containsCall(rig.calls, "case.delete") || containsCall(rig.calls, "dispose") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestDeleteServiceFailsClosedAtEveryIrreversibleBoundary(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*deleteRig)
		absent string
	}{
		{"authority", func(rig *deleteRig) { rig.authority.err = errors.New("authority unavailable") }, "custody.authorized"},
		{"authorization custody", func(rig *deleteRig) { rig.custody.failPhase = Authorized }, "case.delete"},
		{"tombstone", func(rig *deleteRig) { rig.lifecycle.err = errors.New("case unavailable") }, "dispose"},
		{"disposition", func(rig *deleteRig) { rig.disposer.err = errors.New("disposition unavailable") }, "custody.completed"},
		{"completion custody", func(rig *deleteRig) { rig.custody.failPhase = Completed }, "store.commit"},
		{"audit", func(rig *deleteRig) { rig.auditor.appendErr = errors.New("audit unavailable") }, "store.commit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newDeleteRig(t)
			test.mutate(rig)
			result, err := rig.service.Execute(t.Context(), rig.command)
			if err == nil || result.Receipt.ReceiptDigest != "" || containsCall(rig.calls, test.absent) {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestDeleteServiceResumesEveryDurableProgressPhase(t *testing.T) {
	t.Run("authorized", func(t *testing.T) {
		rig := newDeleteRig(t)
		rig.lifecycle.err = errors.New("case unavailable")
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil || rig.store.progress.Phase != Authorized {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.lifecycle.err, rig.calls = nil, nil
		result, err := rig.service.Execute(t.Context(), rig.command)
		if err != nil || ValidateReceipt(result.Receipt) != nil || containsCall(rig.calls, "custody.authorized") ||
			!containsCall(rig.calls, "custody.recover") || !containsCall(rig.calls, "case.delete") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
	t.Run("tombstoned", func(t *testing.T) {
		rig := newDeleteRig(t)
		rig.disposer.err = errors.New("disposition unavailable")
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil || rig.store.progress.Phase != Tombstoned {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.disposer.err, rig.calls = nil, nil
		result, err := rig.service.Execute(t.Context(), rig.command)
		if err != nil || ValidateReceipt(result.Receipt) != nil || containsCall(rig.calls, "case.delete") ||
			containsCall(rig.calls, "custody.authorized") || !containsCall(rig.calls, "dispose") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
	t.Run("disposed", func(t *testing.T) {
		rig := newDeleteRig(t)
		rig.custody.failPhase = Completed
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil || rig.store.progress.Phase != Disposed {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.custody.failPhase, rig.calls = "", nil
		result, err := rig.service.Execute(t.Context(), rig.command)
		if err != nil || ValidateReceipt(result.Receipt) != nil || containsCall(rig.calls, "dispose") ||
			!containsCall(rig.calls, "disposition.recover") || !containsCall(rig.calls, "custody.completed") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
	t.Run("custodied", func(t *testing.T) {
		rig := newDeleteRig(t)
		rig.auditor.appendErr = errors.New("audit unavailable")
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil || rig.store.progress.Phase != Custodied {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.auditor.appendErr, rig.calls = nil, nil
		result, err := rig.service.Execute(t.Context(), rig.command)
		if err != nil || ValidateReceipt(result.Receipt) != nil || containsCall(rig.calls, "dispose") ||
			containsCall(rig.calls, "custody.completed") || !containsCall(rig.calls, "disposition.recover") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
}

func TestDeleteServiceRejectsChangedCompletedReplay(t *testing.T) {
	rig := newDeleteRig(t)
	if _, err := rig.service.Execute(t.Context(), rig.command); err != nil {
		t.Fatal(err)
	}
	changed := rig.command
	changedReason := lifecycleDigest("changed-delete-reason")
	changed.ReasonDigest = &changedReason
	rig.calls = nil
	result, err := rig.service.Execute(t.Context(), changed)
	if CodeOf(err) != Denied || Reason(err) != string(ReasonChangedReplay) ||
		result.Receipt.ReceiptDigest != "" || containsCall(rig.calls, "authority") || containsCall(rig.calls, "dispose") {
		t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
	}
}

func TestDeleteServiceRejectsTamperedDispositionOnReplay(t *testing.T) {
	rig := newDeleteRig(t)
	first, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil {
		t.Fatal(err)
	}
	digest := *first.Receipt.DispositionAttestationDigest
	tampered := rig.disposer.values[digest]
	tampered.Objects[0].EncryptedObjectDigest = lifecycleDigest("substituted-encrypted-object")
	rig.disposer.values[digest] = tampered
	rig.calls = nil
	result, err := rig.service.Execute(t.Context(), rig.command)
	if CodeOf(err) != Denied || Reason(err) != "delete_replay_disposition_invalid" ||
		result.Receipt.ReceiptDigest != "" || containsCall(rig.calls, "dispose") {
		t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
	}
}

func TestDeleteServiceExactReplayVerifiesDispositionAndCustody(t *testing.T) {
	rig := newDeleteRig(t)
	first, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil {
		t.Fatal(err)
	}
	rig.calls = nil
	second, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil || !second.Replayed || second.Receipt.ReceiptDigest != first.Receipt.ReceiptDigest ||
		containsCall(rig.calls, "dispose") || containsCall(rig.calls, "case.delete") ||
		!containsCall(rig.calls, "disposition.recover") {
		t.Fatalf("calls=%v result=%+v err=%v", rig.calls, second, err)
	}
}

type deleteRig struct {
	service   *DeleteService
	command   Command
	calls     []string
	cases     *exportCases
	lifecycle *holdLifecycle
	authority *deleteAuthority
	custody   *exportCustody
	disposer  *deleteDisposer
	auditor   *exportAuditor
	store     *holdStore
}

func newDeleteRig(t *testing.T) *deleteRig {
	t.Helper()
	rig := &deleteRig{}
	now := lifecycleTestNow
	manifest := validExportManifest(t)
	command := validLifecycleCommand(Delete)
	command.ArtifactSetDigest = &manifest.ArtifactSetDigest
	last := now.Add(-time.Minute)
	command.ExpectedCustodyHead = CustodyHead{Case: command.Case, Sequence: 2,
		ChainHash: lifecycleDigest("delete-head"), LastRecordAt: &last}
	evidence := VerifiedEvidenceSet{Case: command.Case, Artifacts: manifest.Artifacts, Components: manifest.Components,
		ArtifactSetDigest: manifest.ArtifactSetDigest, LineageDigest: lifecycleDigest("lineage")}
	evidence.ComponentSetDigest, _ = ComponentSetBindingDigest(evidence.Components)
	rig.cases = &exportCases{calls: &rig.calls, snapshot: CaseSnapshot{Case: command.Case, State: "open",
		Classification: "restricted", Revision: command.ExpectedCaseRevision, RetainUntil: now.Add(-time.Hour),
		ProvenanceDigest: lifecycleDigest("case-provenance")}}
	rig.lifecycle = &holdLifecycle{calls: &rig.calls, cases: rig.cases}
	rig.authority = &deleteAuthority{calls: &rig.calls, now: now}
	rig.custody = &exportCustody{calls: &rig.calls, head: command.ExpectedCustodyHead, now: now}
	rig.disposer = &deleteDisposer{callsLog: &rig.calls, now: now}
	rig.auditor = &exportAuditor{calls: &rig.calls}
	rig.store = &holdStore{calls: &rig.calls, cases: rig.cases}
	service, err := NewDeleteService(rig.authority, rig.cases, rig.lifecycle,
		exportEvidence{calls: &rig.calls, value: evidence}, rig.custody, rig.disposer,
		rig.store, rig.auditor, exportClock{now})
	if err != nil {
		t.Fatal(err)
	}
	rig.service, rig.command = service, command
	return rig
}

type deleteAuthority struct {
	calls  *[]string
	now    time.Time
	err    error
	mutate func(*Decision)
}

func (stub *deleteAuthority) AuthorizeEvidenceLifecycle(_ context.Context,
	request AuthorizationRequest) (Decision, error) {
	*stub.calls = append(*stub.calls, "authority")
	if stub.err != nil {
		return Decision{}, stub.err
	}
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID:          lifecycleUUID("delete-decision-" + request.AuthorizationDigest),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Operation: Delete, Case: request.Command.Case, ActorID: request.Command.ActorID,
		ActorRevision: request.Command.ActorRevision, ArtifactSetDigest: request.ArtifactSetDigest,
		PolicyDigest: request.Command.PolicyDigest, ApprovalDigest: request.Command.ApprovalDigest,
		RevocationDigest: lifecycleDigest("delete-revocation"), ExpectedCaseRevision: request.CaseRevision,
		ExpectedCustodyHead: request.CurrentCustodyHead, Outcome: Allow, ReasonCode: ReasonAuthorized,
		IssuedAt: stub.now, ExpiresAt: stub.now.Add(30 * time.Minute), Revision: 1}
	if stub.mutate != nil {
		stub.mutate(&value)
	}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value, nil
}

type deleteDisposer struct {
	callsLog *[]string
	now      time.Time
	calls    int
	err      error
	values   map[string]DispositionAttestation
}

func (stub *deleteDisposer) DisposeEvidence(_ context.Context,
	request DispositionRequest) (DispositionAttestation, error) {
	*stub.callsLog = append(*stub.callsLog, "dispose")
	stub.calls++
	if stub.err != nil {
		return DispositionAttestation{}, stub.err
	}
	objects := make([]DispositionObject, len(request.Evidence.Artifacts))
	for index, artifact := range request.Evidence.Artifacts {
		objects[index] = DispositionObject{ArtifactDigest: artifact.Reference.Artifact.Digest,
			EncryptedObjectDigest: lifecycleDigest("encrypted-" + artifact.Reference.Artifact.Digest),
			KeyRevision:           2, Outcome: DispositionRemoved,
			OutcomeDigest: lifecycleDigest("outcome-" + artifact.Reference.Artifact.Digest)}
	}
	sort.Slice(objects, func(left, right int) bool { return objects[left].ArtifactDigest < objects[right].ArtifactDigest })
	for index := range objects {
		objects[index].Ordinal = uint16(index + 1)
	}
	value := DispositionAttestation{SchemaVersion: DispositionAttestationSchemaVersion,
		ContractVersion: ContractVersion, AttestationID: lifecycleUUID("delete-attestation"), Case: request.Case,
		OperationID: request.OperationID, ArtifactSetDigest: request.ArtifactSetDigest,
		AuthorizationCustodyReceiptDigest: request.AuthorizationCustodyReceiptDigest,
		LifecycleReceiptDigest:            request.LifecycleReceiptDigest, Mechanism: "encrypted_object_removal",
		Objects: objects, AttemptedAt: stub.now, CompletedAt: stub.now}
	value.AttestationDigest, _ = DispositionBindingDigest(value)
	if stub.values == nil {
		stub.values = make(map[string]DispositionAttestation)
	}
	stub.values[value.AttestationDigest] = value
	return value, nil
}
func (stub *deleteDisposer) RecoverDisposition(_ context.Context, _ domain.CaseRef,
	digest string) (DispositionAttestation, bool, error) {
	*stub.callsLog = append(*stub.callsLog, "disposition.recover")
	value, found := stub.values[digest]
	return value, found, nil
}
