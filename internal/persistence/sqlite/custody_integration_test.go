package sqlite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
)

type custodySQLiteClock struct{ now time.Time }

func (clock custodySQLiteClock) Now() time.Time { return clock.now }

type custodySQLiteAuthority struct{ now time.Time }

func (authority custodySQLiteAuthority) AuthorizeCustody(_ context.Context,
	request custody.AuthorizationRequest) (custody.Decision, error) {
	value := custody.Decision{SchemaVersion: custody.DecisionSchemaVersion,
		ContractVersion: custody.ContractVersion, DecisionID: caseUUID("custody-decision"),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Operation: request.Command.Operation, Phase: request.Command.Phase, Case: request.Command.Case,
		ActorID: request.Command.ActorID, ActorRevision: request.Command.ActorRevision,
		ExpectedCaseRevision: request.CaseRevision, ExpectedHead: request.CurrentHead,
		PolicyDigest: request.Command.PolicyDigest, RevocationDigest: caseDigest("custody-revocation"),
		Outcome: custody.Allow, ReasonCode: custody.ReasonAuthorized, IssuedAt: authority.now,
		ExpiresAt: request.Command.Deadline, Revision: 1}
	value.DecisionDigest, _ = custody.DecisionBindingDigest(value)
	return value, nil
}

type custodySQLiteCases struct{ current custody.CaseSnapshot }

func (store custodySQLiteCases) LoadCase(_ context.Context,
	_ domain.CaseRef) (custody.CaseSnapshot, bool, error) {
	return store.current, true, nil
}

func (custodySQLiteCases) ResolveLifecycleReceipt(context.Context, domain.CaseRef,
	string) (custody.LifecycleReceiptSnapshot, bool, error) {
	return custody.LifecycleReceiptSnapshot{}, false, nil
}

type custodySQLiteEvidence struct{ verified custody.VerifiedEvidence }

func (resolver custodySQLiteEvidence) ResolveEvidence(_ context.Context, _ domain.CaseRef,
	reference custody.EvidenceReference) (custody.VerifiedEvidence, error) {
	if reference != resolver.verified.Reference {
		return custody.VerifiedEvidence{}, errors.New("evidence not found")
	}
	return resolver.verified, nil
}

type custodySQLiteAuditor struct {
	mu       sync.Mutex
	proofs   map[string]custody.AuditProof
	sequence uint64
}

func (auditor *custodySQLiteAuditor) AppendCustodyEvent(_ context.Context,
	event tamperaudit.Event) (custody.AuditProof, error) {
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	eventDigest, err := custodySQLiteAuditDigest(event)
	if err != nil {
		return custody.AuditProof{}, err
	}
	if proof, found := auditor.proofs[eventDigest]; found {
		return proof, nil
	}
	auditor.sequence++
	proof := custody.AuditProof{EventDigest: eventDigest, Sequence: auditor.sequence,
		ChainHash: caseDigest("custody-audit-chain-" + eventDigest)}
	auditor.proofs[eventDigest] = proof
	return proof, nil
}

func (auditor *custodySQLiteAuditor) VerifyCustodyEvent(_ context.Context, _ domain.CaseRef,
	eventDigest, _ string) (custody.AuditProof, error) {
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	proof, found := auditor.proofs[eventDigest]
	if !found {
		return custody.AuditProof{}, errors.New("audit event not found")
	}
	return proof, nil
}

func TestCustodyChainAndResponseSurviveSQLiteRestart(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	path, backup := filepath.Join(root, "coh.sqlite3"), filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	command, current, verified := custodySQLiteFixture(now)
	auditor := &custodySQLiteAuditor{proofs: make(map[string]custody.AuditProof)}
	driver := openCaseSQLite(t, path, backup, now)
	controller, ledger, _ := composeCustodySQLite(t, driver, now, current, verified, auditor)
	created, err := controller.Execute(context.Background(), command)
	if err != nil || created.Replayed || created.Receipt.Sequence != 1 {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	access := command
	access.RequestID = caseUUID("custody-access-request")
	access.IdempotencyKey = "sqlite-custody-access"
	access.Operation, access.Phase = custody.Access, custody.Authorized
	access.SourceIdentityDigest = nil
	purpose := caseDigest("custody-access-purpose")
	access.PurposeDigest = &purpose
	lastRecordAt := now
	access.ExpectedHead = custody.Head{Case: command.Case, Sequence: 1,
		ChainHash: created.Receipt.ChainHash, LastRecordAt: &lastRecordAt}
	accessed, err := controller.Execute(context.Background(), access)
	if err != nil || accessed.Replayed || accessed.Receipt.Sequence != 2 {
		t.Fatalf("access=%+v err=%v", accessed, err)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openCaseSQLite(t, path, backup, now)
	defer driver.Close()
	restartedAuditor := &custodySQLiteAuditor{proofs: make(map[string]custody.AuditProof)}
	restarted, restartedLedger, guarded := composeCustodySQLite(t, driver, now, current, verified, restartedAuditor)
	replayed, err := restarted.Execute(context.Background(), command)
	if err != nil || !replayed.Replayed || replayed.Receipt.ReceiptDigest != created.Receipt.ReceiptDigest {
		t.Fatalf("restart replay=%+v err=%v", replayed, err)
	}
	head, err := restartedLedger.LoadHead(context.Background(), command.Case)
	if err != nil || head.Sequence != 2 || head.ChainHash != accessed.Receipt.ChainHash {
		t.Fatalf("head=%+v err=%v", head, err)
	}
	records, err := restartedLedger.Read(context.Background(), command.Case, 0, 3)
	if err != nil || len(records) != 2 || records[0].RecordDigest != created.Receipt.RecordDigest ||
		records[1].RecordDigest != accessed.Receipt.RecordDigest ||
		records[1].PreviousChainHash != records[0].ChainHash || records[0].Sequence != 1 || records[1].Sequence != 2 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	recovered, found, err := restartedLedger.Recover(context.Background(), command.Case,
		custody.IdempotencyBindingDigest(command.IdempotencyKey))
	if err != nil || !found || recovered.ReceiptDigest != created.Receipt.ReceiptDigest {
		t.Fatalf("recovered=%+v found=%v err=%v", recovered, found, err)
	}
	resolved, found, err := restartedLedger.ResolveReceipt(context.Background(), command.Case,
		created.Receipt.ReceiptDigest)
	if err != nil || !found || resolved.RecordDigest != created.Receipt.RecordDigest {
		t.Fatalf("resolved=%+v found=%v err=%v", resolved, found, err)
	}
	deliveries, err := guarded.ClaimOutbox(context.Background(), workflow.OutboxClaim{
		OrganizationID: command.Case.OrganizationID, TenantID: command.Case.TenantID,
		WorkerID: "custody-restart-test", Limit: 10, LeaseUntil: now.Add(time.Minute)})
	if err != nil || len(deliveries) != 2 || deliveries[0].Message.Topic != "evidence.custody.commit" ||
		deliveries[1].Message.Topic != "evidence.custody.commit" ||
		!custodyOutboxMatchesRecords(deliveries, records) {
		t.Fatalf("outbox=%+v err=%v", deliveries, err)
	}
	if original, err := ledger.Read(context.Background(), command.Case, 0, 2); err == nil || original != nil {
		t.Fatal("closed pre-restart ledger unexpectedly remained usable")
	}
}

func custodyOutboxMatchesRecords(deliveries []workflow.OutboxDelivery, records []custody.Record) bool {
	want := map[string]bool{records[0].AuditEventDigest: true, records[1].AuditEventDigest: true}
	for _, delivery := range deliveries {
		if !want[delivery.Message.PayloadDigest] {
			return false
		}
		delete(want, delivery.Message.PayloadDigest)
	}
	return len(want) == 0
}

func composeCustodySQLite(t *testing.T, driver *sqlite.Store, now time.Time, current custody.CaseSnapshot,
	verified custody.VerifiedEvidence, auditor *custodySQLiteAuditor) (*custody.Controller,
	*custody.RepositoryStore, workflow.Repository) {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := custody.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := custody.New(custodySQLiteAuthority{now: now}, custodySQLiteCases{current: current},
		custodySQLiteEvidence{verified: verified}, ledger, auditor, custodySQLiteClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	return controller, ledger, guarded
}

func custodySQLiteFixture(now time.Time) (custody.Command, custody.CaseSnapshot, custody.VerifiedEvidence) {
	scope := domain.CaseRef{OrganizationID: caseUUID("custody-org"), TenantID: caseUUID("custody-tenant"),
		CaseID: caseUUID("custody-case")}
	reference := custody.EvidenceReference{
		Artifact: domain.ArtifactRef{Digest: caseDigest("custody-artifact"), MediaType: "application/octet-stream",
			Classification: "restricted", Length: 12},
		Manifest: domain.ArtifactRef{Digest: caseDigest("custody-manifest"),
			MediaType: "application/vnd.coh.artifact-manifest+json", Classification: "restricted", Length: 24},
		ManifestProvenanceDigest: caseDigest("custody-manifest-provenance"),
		IngestionReceiptDigest:   caseDigest("custody-ingestion-receipt")}
	source := caseDigest("custody-source")
	command := custody.Command{SchemaVersion: custody.CommandSchemaVersion, ContractVersion: custody.ContractVersion,
		RequestID: caseUUID("custody-request"), IdempotencyKey: "sqlite-custody-acquire",
		Operation: custody.Acquire, Phase: custody.Completed, Case: scope, ActorID: caseUUID("custody-actor"),
		ActorRevision: 2, Subject: reference, SourceIdentityDigest: &source,
		PolicyDigest: caseDigest("custody-policy"), ExpectedCaseRevision: 1,
		ExpectedHead: custody.Head{Case: scope, ChainHash: custody.GenesisHash}, Deadline: now.Add(time.Hour)}
	current := custody.CaseSnapshot{Case: scope, State: "open", Classification: "restricted", Revision: 1,
		RetentionPolicyDigest: caseDigest("custody-retention"), RetainUntil: now.Add(24 * time.Hour),
		ProvenanceDigest: caseDigest("custody-case-provenance")}
	verified := custody.VerifiedEvidence{Reference: reference, SourceIdentityDigest: source,
		VerificationDigest: caseDigest("custody-evidence-verified")}
	return command, current, verified
}

func custodySQLiteAuditDigest(event tamperaudit.Event) (string, error) {
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("COH-CUSTODY-AUDIT-EVENT-V1\x00"), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
