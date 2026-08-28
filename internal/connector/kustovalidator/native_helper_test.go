package kustovalidator

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

type nativeRunnerStub struct {
	call   NativeCall
	result NativeExecution
}

func (stub *nativeRunnerStub) ExecuteKustoNative(_ context.Context, call NativeCall) (NativeExecution, error) {
	stub.call = call
	return stub.result, nil
}

func TestNativeHelperExecutesClosedChunksAndVerifiesProvenance(t *testing.T) {
	var request HelperRequest
	unmarshalFixture(t, "helper-request.json", &request)
	config := NativeConfiguration{ToolName: NativeToolName, ToolVersion: NativeToolVersion,
		ArtifactDigest: request.HelperIdentityExpectation.ArtifactDigest, ManifestDigest: repeatDigest("d")}
	stub := &nativeRunnerStub{result: NativeExecution{AttemptID: request.RequestID, ToolName: config.ToolName,
		ToolVersion: config.ToolVersion, ArtifactDigest: config.ArtifactDigest, ManifestDigest: config.ManifestDigest,
		Operation: NativeOperationName, RequiredTier: "T0", Outcome: "succeeded",
		StandardOutput: readFixture(t, "helper-response.accepted.json")}}
	helper, err := NewNativeHelper(stub, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := helper.Validate(context.Background(), request); err != nil {
		t.Fatalf("native validation: %v", err)
	}
	keys := make([]string, 0, len(stub.call.Inputs))
	for key := range stub.call.Inputs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var joined strings.Builder
	for index, key := range keys {
		if key != "request_chunk_0"+string(rune('0'+index)) {
			t.Fatalf("non-contiguous chunk %q", key)
		}
		joined.WriteString(stub.call.Inputs[key])
	}
	expected, _ := json.Marshal(request)
	if joined.String() != string(expected) || strings.Contains(joined.String(), "actor_id") {
		t.Fatal("helper transport changed or leaked authority")
	}
}

func TestNativeHelperRejectsProvenanceDrift(t *testing.T) {
	var request HelperRequest
	unmarshalFixture(t, "helper-request.json", &request)
	config := NativeConfiguration{ToolName: NativeToolName, ToolVersion: NativeToolVersion,
		ArtifactDigest: request.HelperIdentityExpectation.ArtifactDigest, ManifestDigest: repeatDigest("d")}
	stub := &nativeRunnerStub{result: NativeExecution{AttemptID: request.RequestID, ToolName: config.ToolName,
		ToolVersion: config.ToolVersion, ArtifactDigest: repeatDigest("b"), ManifestDigest: config.ManifestDigest,
		Operation: NativeOperationName, RequiredTier: "T0", Outcome: "succeeded",
		StandardOutput: readFixture(t, "helper-response.accepted.json")}}
	helper, _ := NewNativeHelper(stub, config)
	if _, err := helper.Validate(context.Background(), request); err == nil {
		t.Fatal("tampered provenance accepted")
	}
}

func TestNativeHelperSplitUTF8AndOversize(t *testing.T) {
	input := []byte(strings.Repeat("a", maximumChunkBytes-1) + "☃" + strings.Repeat("b", 10))
	chunks, err := splitUTF8(input)
	if err != nil || len(chunks) != 2 || string(append(chunks[0], chunks[1]...)) != string(input) {
		t.Fatalf("UTF-8 split failed chunks=%d err=%v", len(chunks), err)
	}
	if _, err := splitUTF8(make([]byte, 8*maximumChunkBytes+1)); err == nil {
		t.Fatal("oversize transport accepted")
	}
}
