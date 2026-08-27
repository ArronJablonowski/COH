package evidenceingest

import (
	"context"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type ingestClock struct{ now time.Time }

func (clock ingestClock) Now() time.Time { return clock.now }

type ingestAuthority struct {
	now     time.Time
	outcome string
	calls   int
}

func (authority *ingestAuthority) AuthorizeIngestion(_ context.Context,
	request AuthorizationRequest) (Decision, error) {
	authority.calls++
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID:          deterministicUUID("test-decision", request.Command.RequestID+strconv.Itoa(authority.calls)),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Case: request.Command.Case, ActorID: request.Command.ActorID, ActorRevision: request.Command.ActorRevision,
		ArtifactDigest: request.Command.ExpectedDigest, ArtifactLength: request.Command.ExpectedLength,
		PolicyDigest: request.Command.PolicyDigest, KeyProfileDigest: request.Command.KeyProfileDigest,
		TransportDigest: mustTransportDigest(request.Command.Transport), RevocationDigest: testDigest("revocation"),
		Outcome: authority.outcome, ReasonCode: "ingestion_allowed", IssuedAt: authority.now,
		ExpiresAt: authority.now.Add(time.Minute), Revision: uint64(authority.calls)}
	if value.Outcome == "deny" {
		value.ReasonCode = "policy_denied"
	}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value, nil
}

type ingestTransport struct{ calls int }

func (transport *ingestTransport) VerifyTransport(context.Context, TransportContext) error {
	transport.calls++
	return nil
}

type ingestCases struct {
	snapshot CaseSnapshot
	found    bool
	calls    int
}

func (cases *ingestCases) LoadCase(context.Context, domain.CaseRef) (CaseSnapshot, bool, error) {
	cases.calls++
	return cases.snapshot, cases.found, nil
}

type ingestCAS struct {
	objects      map[string]EncryptedObject
	stageCount   int
	resolveCount int
	failStageAt  int
}

func (store *ingestCAS) Stage(ctx context.Context, request StageRequest, source Source) (EncryptedObject, error) {
	store.stageCount++
	if store.failStageAt == store.stageCount {
		return EncryptedObject{}, newError(Unavailable, "injected_stage_failure", true, nil)
	}
	value := make([]byte, request.ExpectedLength)
	offset := 0
	for offset < len(value) {
		count, err := source.ReadContext(ctx, value[offset:])
		offset += count
		if err != nil && !errors.Is(err, io.EOF) {
			return EncryptedObject{}, err
		}
	}
	var extra [1]byte
	if count, err := source.ReadContext(ctx, extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		return EncryptedObject{}, newError(Denied, "source_length_mismatch", false, err)
	}
	if contentDigest(value) != request.ExpectedDigest {
		return EncryptedObject{}, newError(Denied, "source_digest_mismatch", false, nil)
	}
	object := validEncryptedObject(validCommand(), request.ExpectedDigest, request.ExpectedLength,
		request.MediaType, request.Classification)
	object.Status = Staged
	object.Case = request.Case
	object.EncryptionContextDigest = request.EncryptionContextDigest
	object.LocatorDigest = testDigest("stage-" + request.ExpectedDigest)
	return object, nil
}

func (*ingestCAS) Verify(context.Context, EncryptedObject) error { return nil }
func (store *ingestCAS) Publish(_ context.Context, value EncryptedObject) (EncryptedObject, bool, error) {
	value.Status = Published
	value.LocatorDigest = testDigest("published-" + value.PlaintextDigest)
	if store.objects == nil {
		store.objects = map[string]EncryptedObject{}
	}
	_, replayed := store.objects[value.LocatorDigest]
	store.objects[value.LocatorDigest] = value
	return value, replayed, nil
}
func (store *ingestCAS) Resolve(_ context.Context, reference PublishedObject) (EncryptedObject, error) {
	store.resolveCount++
	value, found := store.objects[reference.LocatorDigest]
	if !found || publishedObject(value) != reference {
		return EncryptedObject{}, newError(Denied, "object_missing", false, nil)
	}
	return value, nil
}
func (*ingestCAS) Abandon(context.Context, EncryptedObject) error { return nil }

type ingestManifests struct {
	receipt Receipt
	found   bool
	commits int
}

func (store *ingestManifests) Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error) {
	return store.receipt, store.found, nil
}
func (store *ingestManifests) Commit(_ context.Context, _, _ string, value Receipt) (Receipt, bool, error) {
	store.commits++
	if store.found {
		return store.receipt, true, nil
	}
	store.receipt, store.found = value, true
	return value, false, nil
}

type ingestAuditor struct {
	events []tamperaudit.Event
	fail   bool
}

func (auditor *ingestAuditor) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	if auditor.fail {
		return errors.New("audit unavailable")
	}
	auditor.events = append(auditor.events, event)
	return nil
}

func TestControllerPublishesArtifactManifestReceiptAndExactReplay(t *testing.T) {
	plaintext := []byte("immutable evidence bytes")
	command := commandForBytes(plaintext)
	controller, authority, transport, cas, manifests, auditor := newIngestController(t, command)
	result, err := controller.Execute(t.Context(), command, &byteSource{value: plaintext})
	if err != nil || result.Replayed || result.Artifact.Digest != command.ExpectedDigest ||
		result.Manifest.MediaType != manifestMediaType || manifests.commits != 1 || cas.stageCount != 2 {
		t.Fatalf("result=%+v commits=%d stages=%d err=%v", result, manifests.commits, cas.stageCount, err)
	}
	if len(auditor.events) != 1 || auditor.events[0].Outcome != "allowed" ||
		result.Receipt.AuditEventDigest == "" || result.Receipt.ManifestProvenanceDigest == "" {
		t.Fatalf("audit=%+v receipt=%+v", auditor.events, result.Receipt)
	}
	stagesBefore := cas.stageCount
	replayed, err := controller.Execute(t.Context(), command, nil)
	if err != nil || !replayed.Replayed || replayed.Receipt.ReceiptDigest != result.Receipt.ReceiptDigest ||
		cas.stageCount != stagesBefore || cas.resolveCount != 4 || authority.calls != 2 || transport.calls != 2 ||
		len(auditor.events) != 3 {
		t.Fatalf("replay=%+v stages=%d resolves=%d authority=%d transport=%d audit=%d err=%v",
			replayed, cas.stageCount, cas.resolveCount, authority.calls, transport.calls, len(auditor.events), err)
	}
}

func TestControllerRepairsAuditAfterCommittedResponseFailure(t *testing.T) {
	plaintext := []byte("audit repair evidence")
	command := commandForBytes(plaintext)
	controller, _, _, _, manifests, auditor := newIngestController(t, command)
	auditor.fail = true
	if _, err := controller.Execute(t.Context(), command, &byteSource{value: plaintext}); CodeOf(err) != Unavailable || !manifests.found {
		t.Fatalf("first error=%v committed=%v", err, manifests.found)
	}
	auditor.fail = false
	result, err := controller.Execute(t.Context(), command, nil)
	if err != nil || !result.Replayed || len(auditor.events) != 2 ||
		auditor.events[0].ReasonCode != "evidence_ingested" || auditor.events[1].ReasonCode != "replay_authorized" {
		t.Fatalf("repair=%+v events=%+v err=%v", result, auditor.events, err)
	}
}

func TestControllerDenialAndManifestFailureReadOrReferenceNothingPartial(t *testing.T) {
	plaintext := []byte("policy denied evidence")
	command := commandForBytes(plaintext)
	controller, authority, _, cas, manifests, auditor := newIngestController(t, command)
	authority.outcome = "deny"
	source := &countingSource{data: plaintext}
	if _, err := controller.Execute(t.Context(), command, source); CodeOf(err) != Denied || source.reads != 0 ||
		cas.stageCount != 0 || manifests.commits != 0 || len(auditor.events) != 1 {
		t.Fatalf("denial code=%s reads=%d stages=%d commits=%d audits=%d", CodeOf(err), source.reads,
			cas.stageCount, manifests.commits, len(auditor.events))
	}

	controller, _, _, cas, manifests, _ = newIngestController(t, command)
	cas.failStageAt = 2
	if _, err := controller.Execute(t.Context(), command, &byteSource{value: plaintext}); CodeOf(err) != Unavailable ||
		manifests.commits != 0 || len(cas.objects) != 1 {
		t.Fatalf("manifest failure code=%s commits=%d published=%d", CodeOf(err), manifests.commits, len(cas.objects))
	}
}

func TestControllerRejectsChangedReplayBeforeTransportOrCAS(t *testing.T) {
	plaintext := []byte("changed replay evidence")
	command := commandForBytes(plaintext)
	controller, _, transport, cas, manifests, _ := newIngestController(t, command)
	if _, err := controller.Execute(t.Context(), command, &byteSource{value: plaintext}); err != nil {
		t.Fatal(err)
	}
	changed := command
	changed.RequestID = deterministicUUID("changed-request", "changed")
	if _, err := controller.Execute(t.Context(), changed, nil); CodeOf(err) != Denied ||
		transport.calls != 1 || cas.resolveCount != 2 || manifests.commits != 1 {
		t.Fatalf("changed replay code=%s transport=%d resolves=%d commits=%d", CodeOf(err),
			transport.calls, cas.resolveCount, manifests.commits)
	}
}

type countingSource struct {
	data   []byte
	offset int
	reads  int
}

func (source *countingSource) ReadContext(ctx context.Context, output []byte) (int, error) {
	source.reads++
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if source.offset == len(source.data) {
		return 0, io.EOF
	}
	count := copy(output, source.data[source.offset:])
	source.offset += count
	return count, nil
}

func newIngestController(t *testing.T, command Command) (*Controller, *ingestAuthority, *ingestTransport,
	*ingestCAS, *ingestManifests, *ingestAuditor) {
	t.Helper()
	authority := &ingestAuthority{now: testNow, outcome: "allow"}
	transport := &ingestTransport{}
	cases := &ingestCases{found: true, snapshot: CaseSnapshot{Case: command.Case, Revision: 2,
		State: "open", Classification: "restricted", ProvenanceDigest: testDigest("case-provenance")}}
	cas := &ingestCAS{objects: map[string]EncryptedObject{}}
	manifests := &ingestManifests{}
	auditor := &ingestAuditor{}
	controller, err := New(authority, transport, cases, cas, manifests, auditor, ingestClock{now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return controller, authority, transport, cas, manifests, auditor
}

func commandForBytes(plaintext []byte) Command {
	value := validCommand()
	value.ExpectedDigest = contentDigest(plaintext)
	value.ExpectedLength = int64(len(plaintext))
	return value
}

func mustTransportDigest(value TransportContext) string {
	digestValue, _ := TransportBindingDigest(value)
	return digestValue
}
