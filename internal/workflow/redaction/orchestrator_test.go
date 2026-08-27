package redaction

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func TestOrchestratorReleasesOnlyAfterCustodyAndAuditVerification(t *testing.T) {
	fixture := newBindingFixture(t)
	dependencies, calls := preflightDependencies(fixture)
	state, derivation := publicationFixture(t, fixture)
	dependencies.custody.proof = validOrchestrationCustodyProof()
	preflightService, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
		dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
	transformer := &transformerStub{derivation: derivation, output: make([]byte, derivation.DerivedArtifact.Length), calls: calls}
	publisher := &publisherStub{calls: calls}
	derivationService, _ := newDerivationService(transformer, publisher)
	auditor := &orchestrationAuditor{calls: calls}
	store := &orchestrationStore{}
	service, _ := newOrchestrator(preflightService, derivationService,
		dependencies.custody, store, auditor, dependencies.clock)
	result, err := service.execute(context.Background(), state.Command)
	if err != nil {
		t.Fatal(err)
	}
	wantTail := []string{"transform", "publish:derived", "publish:mapping", "custody_record", "custody_verify", "audit_append", "audit_verify"}
	if !reflect.DeepEqual((*calls)[len(*calls)-len(wantTail):], wantTail) {
		t.Fatalf("calls=%v", *calls)
	}
	if ValidateReceipt(result.Receipt) != nil || result.Receipt.CustodyReceiptDigest != dependencies.custody.proof.ReceiptDigest ||
		result.Receipt.AuditEventDigest != auditor.proof.EventDigest || result.Receipt.Derived.Artifact != derivation.DerivedArtifact {
		t.Fatalf("receipt=%+v", result.Receipt)
	}
	if auditor.event.SubjectDigest == "" || !containsDigest(auditor.event.EvidenceDigests, dependencies.custody.proof.RecordDigest) ||
		!containsDigest(auditor.event.EvidenceDigests, derivation.Mapping.MappingDigest) {
		t.Fatalf("audit event lost custody/mapping binding: %+v", auditor.event)
	}
}

func TestOrchestratorWithholdsReleaseOnCustodyOrAuditFailure(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*preflightDeps, *orchestrationAuditor)
	}{
		{"custody append", func(d *preflightDeps, _ *orchestrationAuditor) { d.custody.recordErr = errors.New("custody offline") }},
		{"custody verify", func(d *preflightDeps, _ *orchestrationAuditor) {
			d.custody.verifyErr = errors.New("custody verify offline")
		}},
		{"audit append", func(_ *preflightDeps, a *orchestrationAuditor) { a.appendErr = errors.New("audit offline") }},
		{"audit verify", func(_ *preflightDeps, a *orchestrationAuditor) { a.verifyErr = errors.New("audit verify offline") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBindingFixture(t)
			dependencies, calls := preflightDependencies(fixture)
			state, derivation := publicationFixture(t, fixture)
			dependencies.custody.proof = validOrchestrationCustodyProof()
			auditor := &orchestrationAuditor{calls: calls}
			test.configure(&dependencies, auditor)
			preflightService, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
				dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
			transformer := &transformerStub{derivation: derivation, output: make([]byte, derivation.DerivedArtifact.Length), calls: calls}
			publisher := &publisherStub{calls: calls}
			derivationService, _ := newDerivationService(transformer, publisher)
			service, _ := newOrchestrator(preflightService, derivationService, dependencies.custody,
				&orchestrationStore{}, auditor, dependencies.clock)
			result, err := service.execute(context.Background(), state.Command)
			if err == nil || result.Receipt.ReceiptDigest != "" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if test.name[:7] == "custody" && containsCall(*calls, "audit_append") {
				t.Fatalf("audit reached after custody failure: %v", *calls)
			}
		})
	}
}

func TestOrchestratorExactReplayReauthorizesAndReturnsStoredReceiptWithoutRepeatingEffects(t *testing.T) {
	fixture := newBindingFixture(t)
	dependencies, calls := preflightDependencies(fixture)
	state, derivation := publicationFixture(t, fixture)
	dependencies.custody.proof = validOrchestrationCustodyProof()
	preflightService, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
		dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
	transformer := &transformerStub{derivation: derivation, output: make([]byte, derivation.DerivedArtifact.Length), calls: calls}
	publisher := &publisherStub{calls: calls}
	derivationService, _ := newDerivationService(transformer, publisher)
	auditor, store := &orchestrationAuditor{calls: calls}, &orchestrationStore{}
	service, _ := newOrchestrator(preflightService, derivationService, dependencies.custody,
		store, auditor, dependencies.clock)
	created, err := service.execute(context.Background(), state.Command)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]string(nil), (*calls)...)
	replayed, err := service.execute(context.Background(), state.Command)
	if err != nil || !replayed.Replayed || replayed.Receipt.ReceiptDigest != created.Receipt.ReceiptDigest {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	tail := (*calls)[len(before):]
	if containsCall(tail, "transform") || containsCall(tail, "publish:derived") ||
		containsCall(tail, "custody_record") || !containsCall(tail, "authority") || !containsCall(tail, "audit_verify") {
		t.Fatalf("replay calls=%v", tail)
	}
}

func TestOrchestratorResumesPublishedAndCustodiedProgressWithoutDuplicateEffects(t *testing.T) {
	tests := []struct {
		name         string
		firstFailure func(*preflightDeps, *orchestrationAuditor)
		clearFailure func(*preflightDeps, *orchestrationAuditor)
		forbidden    []string
	}{
		{"published", func(d *preflightDeps, _ *orchestrationAuditor) { d.custody.recordErr = errors.New("custody offline") },
			func(d *preflightDeps, _ *orchestrationAuditor) { d.custody.recordErr = nil },
			[]string{"transform", "publish:derived", "publish:mapping"}},
		{"custodied", func(_ *preflightDeps, a *orchestrationAuditor) { a.appendErr = errors.New("audit offline") },
			func(_ *preflightDeps, a *orchestrationAuditor) { a.appendErr = nil },
			[]string{"transform", "publish:derived", "publish:mapping", "custody_record"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBindingFixture(t)
			dependencies, calls := preflightDependencies(fixture)
			state, derivation := publicationFixture(t, fixture)
			dependencies.custody.proof = validOrchestrationCustodyProof()
			auditor, store := &orchestrationAuditor{calls: calls}, &orchestrationStore{}
			test.firstFailure(&dependencies, auditor)
			preflightService, _ := newPreflight(dependencies.authority, dependencies.approvals, dependencies.cases,
				dependencies.plans, dependencies.sources, dependencies.custody, dependencies.clock)
			transformer := &transformerStub{derivation: derivation, output: make([]byte, derivation.DerivedArtifact.Length), calls: calls}
			publisher := &publisherStub{calls: calls}
			derivationService, _ := newDerivationService(transformer, publisher)
			service, _ := newOrchestrator(preflightService, derivationService, dependencies.custody,
				store, auditor, dependencies.clock)
			if _, err := service.execute(context.Background(), state.Command); err == nil {
				t.Fatal("first execution unexpectedly succeeded")
			}
			before := len(*calls)
			test.clearFailure(&dependencies, auditor)
			result, err := service.execute(context.Background(), state.Command)
			if err != nil || result.Receipt.ReceiptDigest == "" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			tail := (*calls)[before:]
			for _, forbidden := range test.forbidden {
				if containsCall(tail, forbidden) {
					t.Fatalf("%s repeated during recovery: %v", forbidden, tail)
				}
			}
		})
	}
}

type orchestrationStore struct {
	progress *Progress
	receipt  *Receipt
}

func (store *orchestrationStore) Recover(_ context.Context, _ domain.CaseRef, _ string) (Receipt, bool, error) {
	if store.receipt == nil {
		return Receipt{}, false, nil
	}
	return cloneReceipt(*store.receipt), true, nil
}

func (store *orchestrationStore) LoadProgress(_ context.Context, _ domain.CaseRef, _ string) (Progress, bool, error) {
	if store.progress == nil {
		return Progress{}, false, nil
	}
	return cloneProgress(*store.progress), true, nil
}

func (store *orchestrationStore) Advance(_ context.Context, _ string, _ uint64,
	value Progress) (Progress, bool, error) {
	if store.progress != nil && store.progress.Revision >= value.Revision {
		return cloneProgress(*store.progress), true, nil
	}
	copyValue := cloneProgress(value)
	store.progress = &copyValue
	return cloneProgress(value), false, nil
}

func (store *orchestrationStore) Commit(_ context.Context, _, _ string,
	_ Record, receipt Receipt) (Receipt, bool, error) {
	if store.receipt != nil {
		return cloneReceipt(*store.receipt), true, nil
	}
	copyValue := cloneReceipt(receipt)
	store.receipt = &copyValue
	return cloneReceipt(receipt), false, nil
}

type orchestrationAuditor struct {
	calls     *[]string
	event     tamperaudit.Event
	proof     AuditProof
	appendErr error
	verifyErr error
}

func (auditor *orchestrationAuditor) AppendRedactionEvent(_ context.Context, event tamperaudit.Event) (AuditProof, error) {
	*auditor.calls = append(*auditor.calls, "audit_append")
	auditor.event = event
	if auditor.appendErr != nil {
		return AuditProof{}, auditor.appendErr
	}
	canonical, _ := tamperaudit.CanonicalEvent(event)
	auditor.proof = AuditProof{EventDigest: digest("COH-REDACTION-AUDIT-EVENT-V1\x00", canonical),
		Sequence: 12, ChainHash: testDigest("e")}
	return auditor.proof, nil
}

func (auditor *orchestrationAuditor) VerifyRedactionEvent(_ context.Context, _ domain.CaseRef,
	_, _ string) (AuditProof, error) {
	*auditor.calls = append(*auditor.calls, "audit_verify")
	if auditor.verifyErr != nil {
		return AuditProof{}, auditor.verifyErr
	}
	return auditor.proof, nil
}

func validOrchestrationCustodyProof() CustodyProof {
	return CustodyProof{ReceiptDigest: testDigest("a"), RecordDigest: testDigest("b"),
		ChainHash: testDigest("c"), Sequence: 4, AuditDigest: testDigest("d")}
}

func containsDigest(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
