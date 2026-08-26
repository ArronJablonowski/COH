package agentloop

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/memorynamespace"
	"github.com/ArronJablonowski/COH/internal/workflow/retrievalguard"
)

type memoryLookupStub struct {
	request memorynamespace.GetRequest
	result  memorynamespace.Result
	err     error
}

func (stub *memoryLookupStub) Get(_ context.Context,
	request memorynamespace.GetRequest) (memorynamespace.Result, error) {
	stub.request = request
	return stub.result, stub.err
}

func TestMemoryLookupPassesOnlyExactReadRequest(t *testing.T) {
	request := memorynamespace.GetRequest{SchemaVersion: memorynamespace.GetSchemaVersion, ContractVersion: memorynamespace.ContractVersion,
		RequestID: testRun, ActorID: testActor,
		Namespace: memorynamespace.CaseMemory,
		Scope:     memorynamespace.Scope{OrganizationID: testOrganization, TenantID: testTenant, CaseID: testCase},
		Key:       "investigation.summary", PolicyDigest: testDigestOne,
		Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}
	want := memorynamespace.Result{Record: memorynamespace.Record{Namespace: memorynamespace.CaseMemory,
		Scope: request.Scope, Key: request.Key, Revision: 2, ProvenanceDigest: testDigestTwo,
		Value: domain.ArtifactRef{Digest: testDigestOne, MediaType: "text/plain", Classification: "restricted", Length: 512}}}
	stub := &memoryLookupStub{result: want}
	guard := &retrievalGuardStub{result: guardedResult()}
	activity, err := NewMemoryLookupActivity(stub, guard)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := MemoryLookupRequest{Read: request, Case: testScope(), TaskID: testPlanStep,
		ActorRevision: 4, InspectionIdempotencyKey: "inspect-memory-1",
		InspectionProfile: retrievalguard.InspectionProfile{Name: "strict_data"}}
	got, err := activity.Lookup(context.Background(), wrapped)
	if err != nil || stub.request != request || got.SourceProvenanceDigest != want.Record.ProvenanceDigest ||
		got.Inspection.Sanitized.Digest != testDigestThree || guard.request.Source.Kind != retrievalguard.MemorySource ||
		guard.request.Source.Artifact != want.Record.Value || guard.request.Case != testScope() || guard.request.TaskID != testPlanStep {
		t.Fatalf("request=%+v result=%+v err=%v", stub.request, got, err)
	}
	if _, exposed := reflect.TypeOf(got).FieldByName("Record"); exposed {
		t.Fatal("raw memory record is model-facing")
	}
}

func TestMemoryLookupMapsInvalidAndUnavailable(t *testing.T) {
	stub := &memoryLookupStub{err: errors.New("unavailable")}
	activity, _ := NewMemoryLookupActivity(stub, &retrievalGuardStub{})
	if _, err := activity.Lookup(context.Background(), MemoryLookupRequest{}); Code(err) != Unavailable {
		t.Fatalf("unavailable code=%s err=%v", Code(err), err)
	}
	_, typed := memorynamespace.NewRepositoryStore("", nil)
	stub.err = typed
	if _, err := activity.Lookup(context.Background(), MemoryLookupRequest{}); Code(err) != InvalidInput {
		t.Fatalf("invalid code=%s err=%v", Code(err), err)
	}
}

func TestMemoryLookupSurfaceCannotWriteOrExecute(t *testing.T) {
	port := reflect.TypeOf((*BoundedMemoryLookup)(nil)).Elem()
	if port.NumMethod() != 1 || port.Method(0).Name != "Get" {
		t.Fatalf("port=%v", port)
	}
	activity := reflect.TypeOf(MemoryLookupActivity{})
	if activity.NumField() != 2 || activity.Field(0).Name != "memory" || activity.Field(1).Name != "guard" {
		t.Fatalf("activity=%v", activity)
	}
}
