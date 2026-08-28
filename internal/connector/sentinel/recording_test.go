package sentinel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const sentinelRecordingRoot = "testdata/azure-monitor-v1"

func TestSanitizedAzureMonitorRecordingNormalizesExactly(t *testing.T) {
	config, err := DecodeConfig(readFixture(t, "config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	input := readSentinelRecording(t, "metadata.json")
	metadata, err := normalizeMetadata(config, input)
	if err != nil {
		t.Fatal(err)
	}
	want, err := DecodeMetadata(readFixture(t, "metadata.snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Digest != want.Digest || metadata.WorkspaceResourceID != want.WorkspaceResourceID || len(metadata.Tables) != 2 {
		t.Fatalf("metadata=%+v want=%+v", metadata, want)
	}
}

func TestAzureMonitorRecordingRejectsDuplicateAndPartialInventory(t *testing.T) {
	config, err := DecodeConfig(readFixture(t, "config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"malformed-duplicate.json", "truncated-continuation.json"} {
		if _, err := normalizeMetadata(config, readSentinelRecording(t, name)); queryconnector.Reason(err) != "sentinel_metadata_response_invalid" {
			t.Fatalf("%s err=%v", name, err)
		}
	}
}

func TestAzureMonitorRecordingManifestIsDocumentedBoundedAndSecretFree(t *testing.T) {
	type record struct{ File, Operation, Outcome string }
	var manifest struct {
		SchemaVersion   string   `json:"schema_version"`
		ContractVersion string   `json:"contract_version"`
		Vendor          string   `json:"vendor"`
		Product         string   `json:"product"`
		APIVersion      string   `json:"api_version"`
		Endpoint        string   `json:"endpoint"`
		OAuthAudience   string   `json:"oauth_audience"`
		Origin          string   `json:"origin"`
		SensitiveValues string   `json:"sensitive_values"`
		Documentation   []string `json:"documentation"`
		Records         []record `json:"records"`
	}
	input := readSentinelRecording(t, "fixture-manifest.json")
	if err := json.Unmarshal(input, &manifest); err != nil || manifest.SchemaVersion != "coh.sentinel-vendor-fixture/v1" ||
		manifest.APIVersion != APIVersion || manifest.Endpoint == "" || manifest.OAuthAudience != TokenAudience ||
		len(manifest.Documentation) != 2 || len(manifest.Records) != 4 || manifest.SensitiveValues != "none" {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	for _, item := range manifest.Records {
		value := readSentinelRecording(t, item.File)
		if len(value) == 0 || len(value) > maximumContractBytes {
			t.Fatalf("recording %s size=%d", item.File, len(value))
		}
		lower := strings.ToLower(string(value))
		for _, forbidden := range []string{"access_token", "refresh_token", "client_secret", "authorization", "bearer ", "private_key"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("recording %s contains %q", item.File, forbidden)
			}
		}
	}
}

func readSentinelRecording(t testing.TB, name string) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Join(sentinelRecordingRoot, name))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestRecordingCannotWidenTheTypedOperation(t *testing.T) {
	config, err := DecodeConfig(readFixture(t, "config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	binding := sentinelTestBinding(config)
	binding.Endpoint = "https://management.azure.com"
	if err := validateCallBinding(config, binding); queryconnector.Reason(err) != "sentinel_call_binding_invalid" {
		t.Fatalf("management binding err=%v", err)
	}
	if _, err := (&Adapter{}).Probe(context.Background(), binding.Scope, binding.Authority); err == nil {
		t.Fatal("unconfigured adapter accepted operation")
	}
}
