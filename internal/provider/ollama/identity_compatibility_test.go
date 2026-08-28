package ollama

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestObserveLocalIdentityBuildsCapabilityProviderTuple(t *testing.T) {
	rig := newTestRig(t)
	observed, err := ObserveLocalIdentity(context.Background(), "qwen3:8b", rig.http, testDigest("9"), 7)
	if err != nil {
		t.Fatal(err)
	}
	want := rig.adapter.Capability().Value().Provider
	if observed.Provider != want || len(observed.Capabilities) != 3 {
		t.Fatalf("observation=%+v want=%+v", observed, want)
	}
}

func TestCurrentOllamaMetadataSurfaceIsIdentityBound(t *testing.T) {
	var show showResponse
	if err := decodeExact(readFixture(t, "show.json"), &show); err != nil {
		t.Fatal(err)
	}
	record := modelRecord{Name: "qwen3:8b", Model: "qwen3:8b", ModifiedAt: show.ModifiedAt, Size: 1,
		Digest: testDigest("a")[len("sha256:"):], Details: show.Details,
		Capabilities: append([]string(nil), show.Capabilities...)}
	record.Details.ContextLength = 32768
	record.Details.EmbeddingLength = 4096
	show.Modelfile = "FROM sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	show.Requires = "0.32.12"
	show.ProjectorInfo = map[string]json.RawMessage{"projector.context_length": json.RawMessage(`32768`)}
	show.Tensors = []tensorRecord{{Name: "token_embd.weight", Type: "Q4_K", Shape: []uint64{4096, 32768}}}
	contextLimit, metadataDigest, err := validateShow(show, record)
	if err != nil || contextLimit != 32768 || len(metadataDigest) != 71 || !strings.HasPrefix(metadataDigest, "sha256:") {
		t.Fatalf("context=%d digest=%q err=%v", contextLimit, metadataDigest, err)
	}
}

func TestSparseTagDetailsAreCompletedByBoundShowMetadata(t *testing.T) {
	var show showResponse
	if err := decodeExact(readFixture(t, "show.json"), &show); err != nil {
		t.Fatal(err)
	}
	record := modelRecord{Name: "qwen3:8b", Model: "qwen3:8b", ModifiedAt: show.ModifiedAt, Size: 1,
		Digest: testDigest("a")[len("sha256:"):], Details: modelDetails{Format: show.Details.Format},
		Capabilities: append([]string(nil), show.Capabilities...)}
	if _, _, err := validateShow(show, record); err != nil {
		t.Fatal(err)
	}
	record.Details.Family = "other"
	if _, _, err := validateShow(show, record); Code(err) != providercontract.Denied || Reason(err) != "model_metadata_invalid" {
		t.Fatalf("err=%v", err)
	}
}

func TestCurrentOllamaMetadataDriftFailsClosed(t *testing.T) {
	base := func(t *testing.T) (showResponse, modelRecord) {
		t.Helper()
		var show showResponse
		if err := decodeExact(readFixture(t, "show.json"), &show); err != nil {
			t.Fatal(err)
		}
		record := modelRecord{Name: "qwen3:8b", Model: "qwen3:8b", ModifiedAt: show.ModifiedAt, Size: 1,
			Digest: testDigest("a")[len("sha256:"):], Details: show.Details,
			Capabilities: append([]string(nil), show.Capabilities...)}
		return show, record
	}
	tests := []struct {
		name   string
		mutate func(*showResponse, *modelRecord)
		code   providercontract.ErrorCode
		reason string
	}{
		{"capability drift", func(_ *showResponse, record *modelRecord) {
			record.Capabilities = []string{"completion", "thinking"}
		}, providercontract.Denied, "model_capability_drift"},
		{"duplicate capability", func(show *showResponse, _ *modelRecord) {
			show.Capabilities = append(show.Capabilities, show.Capabilities[0])
		}, providercontract.Conflict, "model_capability_duplicate"},
		{"context drift", func(_ *showResponse, record *modelRecord) {
			record.Details.ContextLength = 16384
		}, providercontract.Denied, "model_context_drift"},
		{"invalid tensor", func(show *showResponse, _ *modelRecord) {
			show.Tensors = []tensorRecord{{Name: "token_embd.weight", Type: "Q4_K", Shape: []uint64{0, 32768}}}
		}, providercontract.InvalidInput, "model_tensor_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			show, record := base(t)
			test.mutate(&show, &record)
			_, _, err := validateShow(show, record)
			if Code(err) != test.code || Reason(err) != test.reason {
				t.Fatalf("code=%s reason=%s err=%v", Code(err), Reason(err), err)
			}
		})
	}
}
