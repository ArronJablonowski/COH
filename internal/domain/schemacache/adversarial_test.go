package schemacache

import (
	"context"
	"encoding/json"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestInvalidConfigurationAndRequestFailClosed(t *testing.T) {
	clock := &testClock{now: baseTime}
	loader := loaderFunc(func(context.Context, queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		return queryconnector.ValidatedSchemaPage{}, nil
	})
	invalid := []Config{
		{},
		{MaximumEntries: 1, MaximumTotalBytes: 10, MaximumEntryBytes: 11, TTL: time.Second, LoadTimeout: time.Second},
		{MaximumEntries: 1, MaximumTotalBytes: 10, MaximumEntryBytes: 10, TTL: 0, LoadTimeout: time.Second},
		{MaximumEntries: MaximumConfiguredEntries + 1, MaximumTotalBytes: 10, MaximumEntryBytes: 10, TTL: time.Second, LoadTimeout: time.Second},
		{MaximumEntries: 1, MaximumTotalBytes: MaximumConfiguredBytes + 1, MaximumEntryBytes: 10, TTL: time.Second, LoadTimeout: time.Second},
		{MaximumEntries: 1, MaximumTotalBytes: 10, MaximumEntryBytes: 10, TTL: MaximumConfiguredTTL + 1, LoadTimeout: time.Second},
		{MaximumEntries: 1, MaximumTotalBytes: 10, MaximumEntryBytes: 10, TTL: time.Second, LoadTimeout: MaximumLoadTimeout + 1},
	}
	for index, config := range invalid {
		if _, err := New(config, loader, clock); Code(err) != InvalidInput {
			t.Fatalf("config %d err=%v", index, err)
		}
	}
	var nilLoader *typedNilLoader
	if _, err := New(testConfig(), nilLoader, clock); Reason(err) != "configuration_invalid" {
		t.Fatalf("typed nil loader err=%v", err)
	}
	cache := newTestCache(t, clock, loader, testConfig())
	request := validRequest(t, "1", "securityevent")
	request.SchemaRequest.CapabilityDigest = digest("9")
	if _, err := cache.Get(context.Background(), request); Reason(err) != "request_invalid" {
		t.Fatalf("capability substitution err=%v", err)
	}
	request = validRequest(t, "1", "securityevent")
	request.SchemaRequest.Scope.ResourceIDs = []string{"zeta", "alpha"}
	if _, err := cache.Get(context.Background(), request); Reason(err) != "request_invalid" {
		t.Fatalf("unsorted scope err=%v", err)
	}
	//lint:ignore SA1012 verifies the public boundary rejects an absent context
	if _, err := cache.Get(nil, validRequest(t, "1", "securityevent")); Reason(err) != "context_required" {
		t.Fatalf("nil context err=%v", err)
	}
}

type typedNilLoader struct{}

func (*typedNilLoader) LoadSchema(context.Context, queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	return queryconnector.ValidatedSchemaPage{}, nil
}

func TestPartialWidenedAndOversizeSchemasAreDenied(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		loader loaderFunc
		config Config
	}{
		{name: "partial", reason: "schema_incomplete_or_mismatched", config: testConfig(),
			loader: func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
				return partialSchemaPage(t, ctx, request), nil
			}},
		{name: "widened", reason: "schema_scope_widened", config: testConfig(),
			loader: func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
				return schemaPage(t, ctx, request, "otherresource"), nil
			}},
		{name: "oversize", reason: "schema_entry_too_large",
			config: Config{MaximumEntries: 2, MaximumTotalBytes: 128, MaximumEntryBytes: 128,
				TTL: time.Minute, LoadTimeout: time.Second},
			loader: func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
				return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
			}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := newTestCache(t, &testClock{now: baseTime}, test.loader, test.config)
			if _, err := cache.Get(context.Background(), validRequest(t, "1", "securityevent")); Code(err) != Denied || Reason(err) != test.reason {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCanceledWaiterDoesNotPoisonSharedLoad(t *testing.T) {
	clock := &testClock{now: baseTime}
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	loader := loaderFunc(func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		calls.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return queryconnector.ValidatedSchemaPage{}, ctx.Err()
		case <-release:
			return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
		}
	})
	cache := newTestCache(t, clock, loader, testConfig())
	request := validRequest(t, "1", "securityevent")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := cache.Get(ctx, request); result <- err }()
	<-started
	cancel()
	if err := <-result; Code(err) != Canceled {
		t.Fatalf("canceled waiter err=%v", err)
	}
	close(release)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		snapshot, err := cache.Get(context.Background(), request)
		if err == nil && (snapshot.Hit() || calls.Load() == 1) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("bounded shared load did not recover")
}

func TestLoaderTimeoutIsTypedAndRetryRecovers(t *testing.T) {
	clock := &testClock{now: baseTime}
	var calls atomic.Int32
	loader := loaderFunc(func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return queryconnector.ValidatedSchemaPage{}, ctx.Err()
		}
		return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
	})
	config := testConfig()
	config.LoadTimeout = 10 * time.Millisecond
	cache := newTestCache(t, clock, loader, config)
	request := validRequest(t, "1", "securityevent")
	if _, err := cache.Get(context.Background(), request); Code(err) != Timeout || Reason(err) != "loader_timeout" {
		t.Fatalf("timeout err=%v", err)
	}
	if snapshot, err := cache.Get(context.Background(), request); err != nil || snapshot.Hit() {
		t.Fatalf("recovery hit=%t err=%v", snapshot.Hit(), err)
	}
}

func TestInvalidationRejectsInFlightInsertion(t *testing.T) {
	clock := &testClock{now: baseTime}
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	loader := loaderFunc(func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		calls.Add(1)
		if calls.Load() == 1 {
			close(started)
			<-release
		}
		return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
	})
	cache := newTestCache(t, clock, loader, testConfig())
	request := validRequest(t, "1", "securityevent")
	result := make(chan error, 1)
	go func() { _, err := cache.Get(context.Background(), request); result <- err }()
	<-started
	if err := cache.Invalidate(context.Background(), Invalidation{OrganizationID: request.SchemaRequest.Scope.OrganizationID,
		TenantID: request.SchemaRequest.Scope.TenantID, SourceID: request.SchemaRequest.Scope.SourceID}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; Code(err) != Conflict || Reason(err) != "load_invalidated" {
		t.Fatalf("inflight result err=%v", err)
	}
	if snapshot, err := cache.Get(context.Background(), request); err != nil || snapshot.Hit() || calls.Load() != 2 {
		t.Fatalf("post-invalidation hit=%t calls=%d err=%v", snapshot.Hit(), calls.Load(), err)
	}
}

func TestPublicBoundaryCannotExecuteOrEvaluatePolicy(t *testing.T) {
	loaderType := reflect.TypeOf((*Loader)(nil)).Elem()
	if loaderType.NumMethod() != 1 || loaderType.Method(0).Name != "LoadSchema" {
		t.Fatalf("loader surface=%v", loaderType)
	}
	cacheType := reflect.TypeOf((*Cache)(nil))
	for _, forbidden := range []string{"Execute", "ValidatePolicy", "FetchCredential", "DoHTTP"} {
		if _, found := cacheType.MethodByName(forbidden); found {
			t.Fatalf("forbidden cache method %s", forbidden)
		}
	}
	request := validRequest(t, "1", "securityevent")
	originalAuthority := request.SchemaRequest.Authority
	loader := loaderFunc(func(ctx context.Context, loaded queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		if loaded.Authority != originalAuthority {
			t.Fatal("cache changed caller-composed authority")
		}
		return schemaPage(t, ctx, loaded, loaded.Scope.ResourceIDs[0]), nil
	})
	cache := newTestCache(t, &testClock{now: baseTime}, loader, testConfig())
	if _, err := cache.Get(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func partialSchemaPage(t *testing.T, ctx context.Context, request queryconnector.SchemaRequest) queryconnector.ValidatedSchemaPage {
	t.Helper()
	handle := queryconnector.HandleRef{HandleID: id("4"), Kind: "schema_cursor", SourceID: request.Scope.SourceID,
		OpaqueDigest: digest("4"), IssuedAt: baseTime.Format(timestampLayout), ExpiresAt: baseTime.Add(time.Minute).Format(timestampLayout)}
	value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, RequestID: request.RequestID, SchemaDigest: digest("6"),
		Entries:    []queryconnector.SchemaEntry{{ResourceID: request.Scope.ResourceIDs[0], Name: "event_id", Type: "string"}},
		NextCursor: &handle, Complete: false, ProvenanceDigest: digest("7")}
	encoded, _ := json.Marshal(value)
	page, err := queryconnector.DecodeSchemaPage(ctx, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return page
}
