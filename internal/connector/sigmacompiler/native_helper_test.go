package sigmacompiler

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

type sigmaClock struct{ now time.Time }

func (clock sigmaClock) Now() time.Time { return clock.now }

type sigmaManifestVerifier struct {
	authority toolregistry.PublisherAuthority
	calls     int
}

func (verifier *sigmaManifestVerifier) VerifySigmaManifest(ctx context.Context,
	input []byte) (toolregistry.VerifiedEnvelope, error) {
	verifier.calls++
	return toolregistry.Verify(ctx, input, verifier.authority)
}

func (verifier *sigmaManifestVerifier) VerifySigmaAttestation(_ context.Context, value HelperAttestation) error {
	if !verifier.authority.Active || validateAttestation(value) != nil {
		return errors.New("helper qualification denied")
	}
	return nil
}

type sigmaRunnerStub struct {
	mutate func(*NativeExecution)
	calls  []NativeCall
}

func (runner *sigmaRunnerStub) ExecuteSigmaNative(_ context.Context, call NativeCall) (NativeExecution, error) {
	runner.calls = append(runner.calls, call)
	request, err := DecodeCompileRequest(joinNativeInputs(call.Inputs))
	if err != nil {
		return NativeExecution{}, err
	}
	result := NativeExecution{AttemptID: call.AttemptID, ToolName: call.ToolName, ToolVersion: call.ToolVersion,
		ArtifactDigest: call.ArtifactDigest, ManifestDigest: call.ManifestDigest, Operation: call.Operation,
		RequiredTier: call.RequiredTier, Target: call.Target, MappingID: call.MappingID,
		MappingRevision: call.MappingRevision, Outcome: "succeeded", StandardOutput: marshalTestResponse(testResponse(request))}
	if runner.mutate != nil {
		runner.mutate(&result)
	}
	return result, nil
}

func TestNativeHelperVerifiesSignedManifestAndReturnsTypedResponse(t *testing.T) {
	request := nativeTestRequest()
	signed, authority, manifestDigest := signedSigmaManifest(t, request.HelperIdentityExpectation.ArtifactDigest)
	verifier := &sigmaManifestVerifier{authority: authority}
	runner := &sigmaRunnerStub{}
	helper, err := NewNativeHelper(runner, verifier, NativeConfiguration{SignedManifest: signed,
		Identity: request.HelperIdentityExpectation, Attestation: nativeTestAttestation(request.HelperIdentityExpectation, manifestDigest),
		Clock: sigmaClock{now: time.Date(2026, 8, 28, 4, 1, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := helper.Compile(context.Background(), request)
	if err != nil || ValidateExchange(request, response) != nil || response.Outcome != "compiled_untrusted" {
		t.Fatalf("typed compile response denied: outcome=%s err=%v", response.Outcome, err)
	}
	if verifier.calls != 1 || len(runner.calls) != 1 {
		t.Fatalf("unexpected lifecycle calls: verifier=%d runner=%d", verifier.calls, len(runner.calls))
	}
	call := runner.calls[0]
	if call.Target != request.Target || call.MappingID != request.Mapping.MappingID ||
		call.MappingRevision != request.Mapping.Revision || call.RequiredTier != "T0" {
		t.Fatalf("backend/mapping binding lost: %+v", call)
	}
}

func TestNativeHelperReverifiesAuthorityBeforeEveryUse(t *testing.T) {
	request := nativeTestRequest()
	signed, authority, manifestDigest := signedSigmaManifest(t, request.HelperIdentityExpectation.ArtifactDigest)
	verifier := &sigmaManifestVerifier{authority: authority}
	runner := &sigmaRunnerStub{}
	helper, err := NewNativeHelper(runner, verifier, NativeConfiguration{SignedManifest: signed,
		Identity: request.HelperIdentityExpectation, Attestation: nativeTestAttestation(request.HelperIdentityExpectation, manifestDigest),
		Clock: sigmaClock{now: time.Date(2026, 8, 28, 4, 1, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := helper.Compile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	verifier.authority.Active = false
	if _, err := helper.Compile(context.Background(), request); queryconnector.Code(err) != queryconnector.Denied ||
		queryconnector.Reason(err) != "pysigma_signature_or_authority" {
		t.Fatalf("revoked publisher was not denied: %v", err)
	}
	if verifier.calls != 2 || len(runner.calls) != 1 {
		t.Fatalf("revoked helper reached execution: verifier=%d runner=%d", verifier.calls, len(runner.calls))
	}
}

func TestNativeHelperDeniesProvenanceAndOutputSubstitution(t *testing.T) {
	request := nativeTestRequest()
	for name, mutate := range map[string]func(*NativeExecution){
		"backend":    func(value *NativeExecution) { value.Target.BackendVersion = "2.2.0" },
		"mapping":    func(value *NativeExecution) { value.MappingRevision++ },
		"artifact":   func(value *NativeExecution) { value.ArtifactDigest = repeatDigest("0") },
		"stderr":     func(value *NativeExecution) { value.StandardError = []byte("secret") },
		"truncation": func(value *NativeExecution) { value.OutputTruncated = true },
	} {
		t.Run(name, func(t *testing.T) {
			helper := newTestNativeHelper(t, request, &sigmaRunnerStub{mutate: mutate})
			if _, err := helper.Compile(context.Background(), request); queryconnector.Code(err) != queryconnector.Denied ||
				queryconnector.Reason(err) != "pysigma_execution_binding" {
				t.Fatalf("substitution was not denied: %v", err)
			}
		})
	}
}

func TestNativeHelperCancellationThenIndependentRecovery(t *testing.T) {
	request := nativeTestRequest()
	signed, authority, manifestDigest := signedSigmaManifest(t, request.HelperIdentityExpectation.ArtifactDigest)
	verifier := &sigmaManifestVerifier{authority: authority}
	runner := &cancelOnceSigmaRunner{delegate: &sigmaRunnerStub{}}
	helper, err := NewNativeHelper(runner, verifier, NativeConfiguration{SignedManifest: signed,
		Identity: request.HelperIdentityExpectation, Attestation: nativeTestAttestation(request.HelperIdentityExpectation, manifestDigest),
		Clock: sigmaClock{now: time.Date(2026, 8, 28, 4, 1, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := helper.Compile(ctx, request); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("cancellation was not typed: %v", err)
	}
	if _, err := helper.Compile(context.Background(), request); err != nil {
		t.Fatalf("independent recovery failed: %v", err)
	}
}

type cancelOnceSigmaRunner struct{ delegate *sigmaRunnerStub }

func (runner *cancelOnceSigmaRunner) ExecuteSigmaNative(ctx context.Context, call NativeCall) (NativeExecution, error) {
	if err := ctx.Err(); err != nil {
		return NativeExecution{}, err
	}
	return runner.delegate.ExecuteSigmaNative(ctx, call)
}

func newTestNativeHelper(t *testing.T, request CompileRequest, runner NativeRunner) *NativeHelper {
	t.Helper()
	signed, authority, manifestDigest := signedSigmaManifest(t, request.HelperIdentityExpectation.ArtifactDigest)
	helper, err := NewNativeHelper(runner, &sigmaManifestVerifier{authority: authority}, NativeConfiguration{
		SignedManifest: signed, Identity: request.HelperIdentityExpectation,
		Attestation: nativeTestAttestation(request.HelperIdentityExpectation, manifestDigest),
		Clock:       sigmaClock{now: time.Date(2026, 8, 28, 4, 1, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	return helper
}

func nativeTestRequest() CompileRequest {
	request := testRequest()
	request.Deadline = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	request.RequestDigest = CompileRequestDigest(request)
	return request
}

func nativeTestAttestation(identity HelperIdentity, manifestDigest string) HelperAttestation {
	value := testAttestation(identity)
	value.ManifestDigest = manifestDigest
	value.Digest = HelperAttestationDigest(value)
	return value
}

func signedSigmaManifest(t *testing.T, artifactDigest string) ([]byte, toolregistry.PublisherAuthority, string) {
	t.Helper()
	manifest := toolregistry.Manifest{SchemaVersion: toolregistry.ManifestSchemaVersion,
		ContractVersion: toolregistry.ContractVersion, ManifestID: "0198d6c4-5111-7111-8111-111111111111",
		ToolName: NativeToolName, ToolVersion: NativeToolVersion, ArtifactDigest: artifactDigest, MaximumActionTier: "T0",
		PublisherID: "0198d6c4-5222-7222-8222-222222222222", ReviewID: "0198d6c4-5333-7333-8333-333333333333",
		ReviewRevision: 1, ReviewDecision: "approved", ReviewerActorIDs: []string{"0198d6c4-5444-7444-8444-444444444444"},
		ThreatModelDigest: repeatDigest("e"), ReviewedAt: "2026-08-26T00:00:00.000000000Z",
		ValidFrom: "2026-08-27T00:00:00.000000000Z", ValidUntil: "2027-08-27T00:00:00.000000000Z",
		Operations: []toolregistry.Operation{NativeOperation()}}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := toolregistry.Decode(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", ed25519.SeedSize)))
	authority := toolregistry.PublisherAuthority{PublisherID: manifest.PublisherID, KeyID: "publisher.pysigma",
		KeyRevision: 1, ApprovalRevision: 1, Active: true, Approved: true, PublicKey: private.Public().(ed25519.PublicKey)}
	message := append([]byte(toolregistry.SignatureDomain), validated.CanonicalBytes()...)
	envelope := toolregistry.Envelope{SchemaVersion: toolregistry.EnvelopeSchemaVersion,
		ContractVersion: toolregistry.ContractVersion, Manifest: validated.Value(), ManifestDigest: validated.Digest,
		PublisherID: authority.PublisherID, PublisherKeyID: authority.KeyID, PublisherKeyRevision: authority.KeyRevision,
		SignatureAlgorithm: toolregistry.SignatureAlgorithm,
		Signature:          base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}
	signed, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return signed, authority, validated.Digest
}

func joinNativeInputs(inputs map[string]string) []byte {
	var builder strings.Builder
	for index := 0; ; index++ {
		value, ok := inputs[fmt.Sprintf("request_chunk_%02d", index)]
		if !ok {
			break
		}
		builder.WriteString(value)
	}
	return []byte(builder.String())
}

func marshalTestResponse(value CompileResponse) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
