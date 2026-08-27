package queryevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var evidenceNow = time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)

func id(suffix string) string { return "0198e300-1000-7000-8000-00000000000" + suffix }
func digest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type testClock struct{ now time.Time }

func (clock testClock) Now() time.Time { return clock.now }

type sourceStub struct {
	data   []byte
	offset int
}

func (source *sourceStub) ReadContext(ctx context.Context, output []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if source.offset == len(source.data) {
		return 0, errors.New("EOF")
	}
	n := copy(output, source.data[source.offset:])
	source.offset += n
	return n, nil
}

type ingestStub struct {
	mu      sync.Mutex
	calls   int
	binding ArtifactBinding
	err     error
}

func (stub *ingestStub) IngestNativeQuery(_ context.Context, _ ArtifactRequest, _ Source) (ArtifactBinding, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls++
	return stub.binding, stub.err
}

type storeStub struct {
	mu                             sync.Mutex
	head                           *Record
	recovered                      map[string]Record
	appendErr, recoverErr, loadErr error
	appends                        int
}

func (stub *storeStub) LoadHead(_ context.Context, _ StreamRef) (Record, bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.loadErr != nil {
		return Record{}, false, stub.loadErr
	}
	if stub.head == nil {
		return Record{}, false, nil
	}
	return *stub.head, true, nil
}
func (stub *storeStub) Recover(_ context.Context, _ StreamRef, key string) (Record, bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.recoverErr != nil {
		return Record{}, false, stub.recoverErr
	}
	value, found := stub.recovered[key]
	return value, found, nil
}
func (stub *storeStub) Append(_ context.Context, expected ExpectedHead, key, transition string, record Record) (Record, bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.appends++
	if stub.appendErr != nil {
		return Record{}, false, stub.appendErr
	}
	if prior, found := stub.recovered[key]; found {
		return prior, true, nil
	}
	if stub.head == nil {
		if expected != (ExpectedHead{}) || record.Revision != 1 {
			return Record{}, false, errors.New("stale head")
		}
	} else if expected.Revision != stub.head.Revision || expected.ProvenanceDigest != stub.head.ProvenanceDigest {
		return Record{}, false, errors.New("stale head")
	}
	if transition != record.TransitionID {
		return Record{}, false, errors.New("transition mismatch")
	}
	copy := record
	stub.head = &copy
	if stub.recovered == nil {
		stub.recovered = map[string]Record{}
	}
	stub.recovered[key] = copy
	return copy, false, nil
}

type auditStub struct {
	mu     sync.Mutex
	events []AuditEvent
	err    error
}

func (stub *auditStub) AppendQueryEvidence(_ context.Context, event AuditEvent) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.events = append(stub.events, event)
	return stub.err
}

func artifact(seed string, length int64) ArtifactBinding {
	classification := "restricted"
	return ArtifactBinding{Artifact: ArtifactRef{Digest: digest(seed), MediaType: "application/vnd.coh.native-query", Classification: classification, Length: length},
		Manifest:                 ArtifactRef{Digest: digest(seed + "-manifest"), MediaType: "application/vnd.coh.artifact-manifest+json", Classification: classification, Length: 512},
		ManifestProvenanceDigest: digest(seed + "-provenance"), IngestionReceiptDigest: digest(seed + "-receipt")}
}

func signedSession(revision uint64, previous string, status, reason string, usage queryruntime.Usage) queryruntime.Session {
	value := queryruntime.Session{SchemaVersion: queryruntime.SessionSchemaVersion, ContractVersion: queryruntime.ContractVersion,
		SessionID: id("6"), Revision: revision, PreviousSessionDigest: previous, QueryID: id("1"), QueryDigest: digest("query"),
		BoundsDecisionDigest: digest("bounds"), ExecutionDigest: digest("execution"), AttemptID: id("7"), OrganizationID: id("2"),
		TenantID: id("3"), ActorID: id("5"), SourceID: "sentinel-prod", Mode: "interactive",
		EffectiveLimits: queryconnector.Limits{MaximumRows: 100, MaximumBytes: 1000, MaximumDurationMillis: 60000, MaximumPages: 3, MaximumSlices: 2, MaximumCostMillionths: 100, RequestsPerMinute: 5},
		Usage:           usage, Status: status, ReasonCode: reason, NextPageNumber: 1, PollDelayMillis: 100,
		NextPollAt: evidenceNow.Add(time.Duration(revision-1) * time.Second).Format(timestampLayout), JobHandleDigest: digest("handle"),
		VendorProvenanceDigest: digest("vendor"), StartedAt: evidenceNow.Format(timestampLayout),
		UpdatedAt: evidenceNow.Add(time.Duration(revision-1) * time.Second).Format(timestampLayout), Deadline: evidenceNow.Add(5 * time.Minute).Format(timestampLayout)}
	encoded, _ := json.Marshal(value)
	canonical, _ := domaincontract.Canonicalize(encoded)
	sum := sha256.Sum256(append([]byte("COH-QUERY-RUNTIME-SESSION-V1\x00"), canonical...))
	value.SessionDigest = "sha256:" + hex.EncodeToString(sum[:])
	return value
}

func startCommand(native []byte) StartCommand {
	session := signedSession(1, "", "running", "execution_running", queryruntime.Usage{})
	return StartCommand{RequestID: id("8"), IdempotencyKey: "query-start-1", Case: domain.CaseRef{OrganizationID: id("2"), TenantID: id("3"), CaseID: id("4")},
		ActorID: id("5"), ActorRevision: 1, SourceID: "sentinel-prod", QueryDigest: digest("query"), BoundsDecisionDigest: digest("bounds"),
		ExecutionDigest: digest("execution"), ValidatorVersion: "validator-1.0.0", ValidatorProvenanceDigest: digest("validator"),
		IntervalStart: evidenceNow.Add(-time.Hour).Format(timestampLayout), IntervalEnd: evidenceNow.Format(timestampLayout),
		ResourceScopeDigest: digest("scope"), NativeQueryDigest: digestBytes(native), NativeQueryLength: int64(len(native)),
		NativeQueryMediaType: "application/vnd.coh.native-query", Classification: "restricted", PolicyDigest: digest("policy"),
		RuntimeSession: session, Deadline: evidenceNow.Add(time.Minute)}
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fixture(t testing.TB, native []byte) (*Controller, *ingestStub, *storeStub, *auditStub, StartCommand) {
	t.Helper()
	command := startCommand(native)
	ingest := &ingestStub{binding: artifact("native", int64(len(native)))}
	ingest.binding.Artifact.Digest = command.NativeQueryDigest
	store := &storeStub{recovered: map[string]Record{}}
	audit := &auditStub{}
	controller, err := New(ingest, store, audit, testClock{evidenceNow})
	if err != nil {
		t.Fatal(err)
	}
	return controller, ingest, store, audit, command
}
