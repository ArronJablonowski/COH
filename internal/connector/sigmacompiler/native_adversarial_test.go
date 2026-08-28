package sigmacompiler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestNativeHelperDeniesSignatureAttestationAndResponseTamper(t *testing.T) {
	request := nativeTestRequest()
	t.Run("signature", func(t *testing.T) {
		signed, authority, manifestDigest := signedSigmaManifest(t, request.HelperIdentityExpectation.ArtifactDigest)
		var envelope map[string]any
		if err := json.Unmarshal(signed, &envelope); err != nil {
			t.Fatal(err)
		}
		signature := envelope["signature"].(string)
		first := "A"
		if signature[0] == 'A' {
			first = "B"
		}
		envelope["signature"] = first + signature[1:]
		tampered, _ := json.Marshal(envelope)
		helper, err := NewNativeHelper(&sigmaRunnerStub{}, &sigmaManifestVerifier{authority: authority},
			NativeConfiguration{SignedManifest: tampered, Identity: request.HelperIdentityExpectation,
				Attestation: nativeTestAttestation(request.HelperIdentityExpectation, manifestDigest),
				Clock:       sigmaClock{now: time.Date(2026, 8, 28, 4, 1, 0, 0, time.UTC)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := helper.Compile(context.Background(), request); queryconnector.Reason(err) != "pysigma_signature_or_authority" {
			t.Fatalf("tampered signature was not denied: %v", err)
		}
	})
	t.Run("stale_attestation", func(t *testing.T) {
		staleRequest := clone(request)
		staleRequest.Deadline = "2026-10-01T00:00:00Z"
		staleRequest.RequestDigest = CompileRequestDigest(staleRequest)
		signed, authority, manifestDigest := signedSigmaManifest(t, request.HelperIdentityExpectation.ArtifactDigest)
		helper, err := NewNativeHelper(&sigmaRunnerStub{}, &sigmaManifestVerifier{authority: authority},
			NativeConfiguration{SignedManifest: signed, Identity: request.HelperIdentityExpectation,
				Attestation: nativeTestAttestation(request.HelperIdentityExpectation, manifestDigest),
				Clock:       sigmaClock{now: time.Date(2026, 9, 27, 4, 0, 1, 0, time.UTC)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := helper.Compile(context.Background(), staleRequest); queryconnector.Reason(err) != "pysigma_attestation_stale" {
			t.Fatalf("stale runtime attestation was not denied: %v", err)
		}
	})
	for name, output := range map[string][]byte{
		"malformed": []byte(`{"outcome":"compiled_untrusted"}`),
		"oversize":  bytes.Repeat([]byte("x"), MaximumDocumentBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			helper := newTestNativeHelper(t, request, &fixedOutputSigmaRunner{output: output})
			if _, err := helper.Compile(context.Background(), request); queryconnector.Code(err) != queryconnector.Denied {
				t.Fatalf("invalid output was not denied: %v", err)
			}
		})
	}
}

func TestNativeHelperTypesTimeoutAndRecoversAfterCrash(t *testing.T) {
	request := nativeTestRequest()
	request.Deadline = time.Now().UTC().Add(20 * time.Millisecond).Format(time.RFC3339Nano)
	request.RequestDigest = CompileRequestDigest(request)
	timeoutHelper := newTestNativeHelper(t, request, blockingSigmaRunner{})
	if _, err := timeoutHelper.Compile(context.Background(), request); queryconnector.Code(err) != queryconnector.Timeout {
		t.Fatalf("timeout was not typed: %v", err)
	}

	recoveryRequest := nativeTestRequest()
	runner := &failOnceSigmaRunner{delegate: &sigmaRunnerStub{}}
	recoveryHelper := newTestNativeHelper(t, recoveryRequest, runner)
	if _, err := recoveryHelper.Compile(context.Background(), recoveryRequest); queryconnector.Code(err) != queryconnector.Unavailable {
		t.Fatalf("crash was not typed unavailable: %v", err)
	}
	if response, err := recoveryHelper.Compile(context.Background(), recoveryRequest); err != nil || response.Outcome != "compiled_untrusted" {
		t.Fatalf("clean retry did not recover: outcome=%s err=%v", response.Outcome, err)
	}
}

func TestNativeHelperReplayAndConcurrencyAreDeterministicAcrossBackends(t *testing.T) {
	request := nativeTestRequest()
	signed, authority, manifestDigest := signedSigmaManifest(t, request.HelperIdentityExpectation.ArtifactDigest)
	verifier := &sigmaManifestVerifier{authority: authority}
	helper, err := NewNativeHelper(concurrentSigmaRunner{}, verifier, NativeConfiguration{SignedManifest: signed,
		Identity:    request.HelperIdentityExpectation,
		Attestation: nativeTestAttestation(request.HelperIdentityExpectation, manifestDigest),
		Clock:       sigmaClock{now: time.Date(2026, 8, 28, 4, 1, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	requests := make([]CompileRequest, 0, 3)
	for _, target := range targetMatrix {
		if target.Target == "security-onion" {
			continue
		}
		candidate := clone(request)
		candidate.Target = target
		candidate.RequestDigest = CompileRequestDigest(candidate)
		requests = append(requests, candidate)
	}
	expected := make(map[string]CompileResponse, len(requests))
	for _, candidate := range requests {
		response, compileErr := helper.Compile(context.Background(), candidate)
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		expected[candidate.Target.Target] = response
		replayed, replayErr := helper.Compile(context.Background(), candidate)
		if replayErr != nil || !reflect.DeepEqual(replayed, response) {
			t.Fatalf("%s replay drifted: %v", candidate.Target.Target, replayErr)
		}
	}
	var wait sync.WaitGroup
	errorsFound := make(chan error, 24)
	for iteration := 0; iteration < 8; iteration++ {
		for _, candidate := range requests {
			candidate := candidate
			wait.Add(1)
			go func() {
				defer wait.Done()
				response, compileErr := helper.Compile(context.Background(), candidate)
				if compileErr != nil || !reflect.DeepEqual(response, expected[candidate.Target.Target]) {
					errorsFound <- errors.New("concurrent compilation drift")
				}
			}()
		}
	}
	wait.Wait()
	close(errorsFound)
	for compileErr := range errorsFound {
		t.Fatal(compileErr)
	}
}

type fixedOutputSigmaRunner struct{ output []byte }

func (runner *fixedOutputSigmaRunner) ExecuteSigmaNative(_ context.Context, call NativeCall) (NativeExecution, error) {
	return NativeExecution{AttemptID: call.AttemptID, ToolName: call.ToolName, ToolVersion: call.ToolVersion,
		ArtifactDigest: call.ArtifactDigest, ManifestDigest: call.ManifestDigest, Operation: call.Operation,
		RequiredTier: call.RequiredTier, Target: call.Target, MappingID: call.MappingID,
		MappingRevision: call.MappingRevision, Outcome: "succeeded", StandardOutput: runner.output}, nil
}

type blockingSigmaRunner struct{}

func (blockingSigmaRunner) ExecuteSigmaNative(ctx context.Context, _ NativeCall) (NativeExecution, error) {
	<-ctx.Done()
	return NativeExecution{}, ctx.Err()
}

type failOnceSigmaRunner struct {
	mutex    sync.Mutex
	failed   bool
	delegate *sigmaRunnerStub
}

func (runner *failOnceSigmaRunner) ExecuteSigmaNative(ctx context.Context, call NativeCall) (NativeExecution, error) {
	runner.mutex.Lock()
	if !runner.failed {
		runner.failed = true
		runner.mutex.Unlock()
		return NativeExecution{}, errors.New("helper exited")
	}
	runner.mutex.Unlock()
	return runner.delegate.ExecuteSigmaNative(ctx, call)
}

type concurrentSigmaRunner struct{}

func (concurrentSigmaRunner) ExecuteSigmaNative(_ context.Context, call NativeCall) (NativeExecution, error) {
	request, err := DecodeCompileRequest(joinNativeInputs(call.Inputs))
	if err != nil {
		return NativeExecution{}, err
	}
	return (&fixedOutputSigmaRunner{output: marshalTestResponse(testResponse(request))}).ExecuteSigmaNative(context.Background(), call)
}
