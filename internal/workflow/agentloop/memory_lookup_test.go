package agentloop

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/workflow/memorynamespace"
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
		Scope: request.Scope, Key: request.Key, ProvenanceDigest: testDigestTwo}}
	stub := &memoryLookupStub{result: want}
	activity, err := NewMemoryLookupActivity(stub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := activity.Lookup(context.Background(), request)
	if err != nil || stub.request != request || got.Record.ProvenanceDigest != want.Record.ProvenanceDigest {
		t.Fatalf("request=%+v result=%+v err=%v", stub.request, got, err)
	}
}

func TestMemoryLookupMapsInvalidAndUnavailable(t *testing.T) {
	stub := &memoryLookupStub{err: errors.New("unavailable")}
	activity, _ := NewMemoryLookupActivity(stub)
	if _, err := activity.Lookup(context.Background(), memorynamespace.GetRequest{}); Code(err) != Unavailable {
		t.Fatalf("unavailable code=%s err=%v", Code(err), err)
	}
	_, typed := memorynamespace.NewRepositoryStore("", nil)
	stub.err = typed
	if _, err := activity.Lookup(context.Background(), memorynamespace.GetRequest{}); Code(err) != InvalidInput {
		t.Fatalf("invalid code=%s err=%v", Code(err), err)
	}
}

func TestMemoryLookupSurfaceCannotWriteOrExecute(t *testing.T) {
	port := reflect.TypeOf((*BoundedMemoryLookup)(nil)).Elem()
	if port.NumMethod() != 1 || port.Method(0).Name != "Get" {
		t.Fatalf("port=%v", port)
	}
	activity := reflect.TypeOf(MemoryLookupActivity{})
	if activity.NumField() != 1 || activity.Field(0).Name != "memory" {
		t.Fatalf("activity=%v", activity)
	}
}
