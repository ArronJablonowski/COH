package splunk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestRecordedVendorFixturesAreSanitizedAndStrict(t *testing.T) {
	for _, name := range []string{"server-info.json", "current-context.json", "indexes.json", "registered-fields.json",
		"privilege-denied.json", "malformed-duplicate.json"} {
		input := readSplunkFixture(t, name)
		lower := strings.ToLower(string(input))
		for _, forbidden := range []string{"authorization", "bearer", "splunk ", "sessionkey", "token", "sid", "native_text"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("fixture %s exposes %q", name, forbidden)
			}
		}
	}
	if err := decodeVendor(readSplunkFixture(t, "malformed-duplicate.json"), &map[string]any{}); err == nil {
		t.Fatal("duplicate vendor key accepted")
	}
}

func TestHTTPClientRejectsMalformedPartialAndInvalidLeaseEvidence(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		decision string
		reason   string
	}{
		{"duplicate response", "malformed-duplicate.json", splunkTestDigest("8"), "splunk_server_info_response_invalid"},
		{"partial response", "indexes.json", splunkTestDigest("8"), "splunk_server_info_response_invalid"},
		{"lease receipt", "server-info.json", "invalid", "splunk_transport_receipt_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write(readSplunkFixture(t, test.fixture))
			}))
			defer server.Close()
			config, roots := splunkHTTPTestConfig(t, server)
			client, err := NewHTTPClient(config, &splunkCredentialStub{token: []byte("ephemeral"), decision: test.decision}, roots)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = client.ServerInfo(context.Background(), splunkTestBinding("splunk.server_info"))
			if queryconnector.Reason(err) != test.reason || strings.Contains(err.Error(), "ephemeral") {
				t.Fatalf("reason=%s err=%v", queryconnector.Reason(err), err)
			}
		})
	}
}

func TestDiscoveryDoesNotPublishUnconfiguredVendorFields(t *testing.T) {
	adapter, client, _ := splunkTestAdapter(t, 256)
	client.fields.Fields = append(client.fields.Fields, RegisteredField{Name: "unconfigured_private_field"})
	capability, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority)
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.DiscoverSchema(context.Background(), splunkSchemaRequest(capability.Digest()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(page.CanonicalBytes()), "unconfigured_private_field") {
		t.Fatalf("field leaked: %s", page.CanonicalBytes())
	}
}

func TestConcurrentOpaqueCursorReplayIsDeterministic(t *testing.T) {
	adapter, _, _ := splunkTestAdapter(t, 1)
	capability, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority)
	if err != nil {
		t.Fatal(err)
	}
	request := splunkSchemaRequest(capability.Digest())
	first, err := adapter.DiscoverSchema(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Cursor = first.Value().NextCursor
	const workers = 32
	digests := make(chan string, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			page, loadErr := adapter.DiscoverSchema(context.Background(), request)
			if loadErr != nil {
				errors <- loadErr
				return
			}
			digests <- page.Digest()
		}()
	}
	group.Wait()
	close(digests)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	want := ""
	for digest := range digests {
		if want == "" {
			want = digest
		}
		if digest != want {
			t.Fatalf("digest %s != %s", digest, want)
		}
	}
}
