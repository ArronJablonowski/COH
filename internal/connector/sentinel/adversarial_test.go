package sentinel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestHTTPClientCancellationDeadlineOutageAndRecovery(t *testing.T) {
	t.Run("pre-canceled", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer server.Close()
		config, roots := sentinelHTTPTestConfig(t, server)
		credentials := &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}
		client, _ := newHTTPClient(config, credentials, roots, server.URL)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := client.Metadata(ctx, MetadataRequest{Binding: sentinelTestBinding(config)}); queryconnector.Code(err) != queryconnector.Canceled || credentials.uses != 0 {
			t.Fatalf("err=%v uses=%d", err, credentials.uses)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			<-request.Context().Done()
		}))
		defer server.Close()
		config, roots := sentinelHTTPTestConfig(t, server)
		client, _ := newHTTPClient(config, &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}, roots, server.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if _, _, err := client.Metadata(ctx, MetadataRequest{Binding: sentinelTestBinding(config)}); queryconnector.Code(err) != queryconnector.Timeout {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("outage recovery", func(t *testing.T) {
		var attempts atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			if attempts.Add(1) == 1 {
				http.Error(writer, "redacted outage", http.StatusServiceUnavailable)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(readSentinelRecording(t, "metadata.json"))
		}))
		defer server.Close()
		config, roots := sentinelHTTPTestConfig(t, server)
		credentials := &sentinelCredentialStub{token: []byte("token"), decision: sentinelTestDigest("8")}
		client, _ := newHTTPClient(config, credentials, roots, server.URL)
		request := MetadataRequest{Binding: sentinelTestBinding(config)}
		if _, _, err := client.Metadata(context.Background(), request); queryconnector.Code(err) != queryconnector.Unavailable ||
			strings.Contains(err.Error(), "outage") {
			t.Fatalf("outage err=%v", err)
		}
		metadata, _, err := client.Metadata(context.Background(), request)
		if err != nil || metadata.Digest == "" || attempts.Load() != 2 || credentials.uses != 2 {
			t.Fatalf("metadata=%+v attempts=%d uses=%d err=%v", metadata, attempts.Load(), credentials.uses, err)
		}
	})
}

func TestHTTPClientRejectsInvalidLeaseDecisionReceipt(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(readSentinelRecording(t, "metadata.json"))
	}))
	defer server.Close()
	config, roots := sentinelHTTPTestConfig(t, server)
	client, _ := newHTTPClient(config, &sentinelCredentialStub{token: []byte("token"), decision: "invalid"}, roots, server.URL)
	if _, _, err := client.Metadata(context.Background(), MetadataRequest{Binding: sentinelTestBinding(config)}); queryconnector.Reason(err) != "sentinel_transport_receipt_invalid" {
		t.Fatalf("err=%v", err)
	}
}

func TestAdapterRejectsCursorTamperTheftAndCapabilitySubstitution(t *testing.T) {
	adapter, _, config := sentinelTestAdapter(t, 1)
	binding := sentinelTestBinding(config)
	capability, err := adapter.Probe(context.Background(), binding.Scope, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	request := sentinelSchemaRequest(config, capability.Digest())
	first, err := adapter.DiscoverSchema(context.Background(), request)
	if err != nil || first.Value().NextCursor == nil {
		t.Fatalf("first=%+v err=%v", first.Value(), err)
	}

	tampered := *first.Value().NextCursor
	tampered.OpaqueDigest = sentinelTestDigest("9")
	request.Cursor = &tampered
	if _, err := adapter.DiscoverSchema(context.Background(), request); queryconnector.Reason(err) != "sentinel_schema_cursor_mismatch" {
		t.Fatalf("cursor tamper err=%v", err)
	}

	stolen := *first.Value().NextCursor
	stolen.HandleID = "018f1f2e-7a6b-7c8d-8e9f-000000000199"
	request.Cursor = &stolen
	if _, err := adapter.DiscoverSchema(context.Background(), request); queryconnector.Reason(err) != "sentinel_schema_cursor_stale" {
		t.Fatalf("cursor theft err=%v", err)
	}

	request.Cursor = nil
	request.CapabilityDigest = sentinelTestDigest("9")
	if _, err := adapter.DiscoverSchema(context.Background(), request); queryconnector.Reason(err) != "sentinel_capability_stale" {
		t.Fatalf("capability substitution err=%v", err)
	}
}
