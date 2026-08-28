package sigmacompiler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

// NativeCall is authority-neutral. The broker-owned runner supplies current
// execution authority and must enforce the signed operation's sandbox limits.
type NativeCall struct {
	AttemptID       string
	ToolName        string
	ToolVersion     string
	ArtifactDigest  string
	ManifestDigest  string
	Operation       string
	RequiredTier    string
	Target          TargetBinding
	MappingID       string
	MappingRevision uint64
	Inputs          map[string]string
}

// NativeExecution echoes every security-relevant binding. StandardOutput is
// decoded internally and is never released by this adapter.
type NativeExecution struct {
	AttemptID       string
	ToolName        string
	ToolVersion     string
	ArtifactDigest  string
	ManifestDigest  string
	Operation       string
	RequiredTier    string
	Target          TargetBinding
	MappingID       string
	MappingRevision uint64
	Outcome         string
	StandardOutput  []byte
	StandardError   []byte
	OutputTruncated bool
}

type NativeRunner interface {
	ExecuteSigmaNative(context.Context, NativeCall) (NativeExecution, error)
}

// HelperTrust must consult current publisher and qualification authority.
// Production implementations can therefore reject a revoked key, runtime, or
// package closure between calls.
type HelperTrust interface {
	VerifySigmaManifest(context.Context, []byte) (toolregistry.VerifiedEnvelope, error)
	VerifySigmaAttestation(context.Context, HelperAttestation) error
}

type NativeConfiguration struct {
	SignedManifest []byte
	Identity       HelperIdentity
	Attestation    HelperAttestation
	Clock          NativeClock
}

type NativeClock interface{ Now() time.Time }

type NativeHelper struct {
	runner NativeRunner
	trust  HelperTrust
	config NativeConfiguration
}

func NewNativeHelper(runner NativeRunner, trust HelperTrust, config NativeConfiguration) (*NativeHelper, error) {
	if runner == nil || trust == nil || config.Clock == nil || len(config.SignedManifest) == 0 ||
		validateIdentity(config.Identity) != nil || validateAttestation(config.Attestation) != nil ||
		config.Attestation.Identity != config.Identity {
		return nil, queryconnector.NewError(queryconnector.InvalidInput, "pysigma_native_configuration", nil)
	}
	config.SignedManifest = append([]byte(nil), config.SignedManifest...)
	config.Attestation = clone(config.Attestation)
	return &NativeHelper{runner: runner, trust: trust, config: config}, nil
}

// Compile verifies admission, applies the tighter caller/helper deadline,
// executes once, and returns only a strict typed response.
func (helper *NativeHelper) Compile(ctx context.Context, request CompileRequest) (CompileResponse, error) {
	if helper == nil || helper.runner == nil || helper.trust == nil {
		return CompileResponse{}, nativeError(queryconnector.Unavailable, "pysigma_helper_unavailable", nil)
	}
	if err := nativeContextError(ctx); err != nil {
		return CompileResponse{}, err
	}
	if validateRequest(request) != nil || request.HelperIdentityExpectation != helper.config.Identity {
		return CompileResponse{}, nativeError(queryconnector.Denied, "pysigma_request_binding", nil)
	}
	now := helper.config.Clock.Now().UTC()
	deadline, err := time.Parse(time.RFC3339Nano, request.Deadline)
	if err != nil || !deadline.After(now) {
		return CompileResponse{}, nativeError(queryconnector.Timeout, "pysigma_deadline", err)
	}
	observedAt, observedOK := parseTimestamp(helper.config.Attestation.ObservedAt)
	validUntil, validOK := parseTimestamp(helper.config.Attestation.ValidUntil)
	if !observedOK || !validOK || observedAt.After(now) || !validUntil.After(now) {
		return CompileResponse{}, nativeError(queryconnector.Denied, "pysigma_attestation_stale", nil)
	}
	verified, err := helper.trust.VerifySigmaManifest(ctx, helper.config.SignedManifest)
	if err != nil {
		return CompileResponse{}, nativeError(queryconnector.Denied, "pysigma_signature_or_authority", err)
	}
	if err := helper.trust.VerifySigmaAttestation(ctx, helper.config.Attestation); err != nil {
		return CompileResponse{}, nativeError(queryconnector.Denied, "pysigma_runtime_or_qualification", err)
	}
	manifest := verified.Manifest()
	if manifest.ToolName != NativeToolName || manifest.ToolVersion != NativeToolVersion ||
		manifest.ArtifactDigest != helper.config.Identity.ArtifactDigest || manifest.MaximumActionTier != "T0" ||
		helper.config.Attestation.ManifestDigest != verified.ManifestDigest ||
		len(manifest.Operations) != 1 || !reflect.DeepEqual(manifest.Operations[0], NativeOperation()) {
		return CompileResponse{}, nativeError(queryconnector.Denied, "pysigma_manifest_binding", nil)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return CompileResponse{}, nativeError(queryconnector.InvalidInput, "pysigma_request_encoding", err)
	}
	chunks, err := splitNativeUTF8(encoded)
	if err != nil {
		return CompileResponse{}, err
	}
	inputs := make(map[string]string, len(chunks))
	for index, chunk := range chunks {
		inputs[fmt.Sprintf("request_chunk_%02d", index)] = string(chunk)
	}
	call := NativeCall{AttemptID: request.RequestID, ToolName: NativeToolName, ToolVersion: NativeToolVersion,
		ArtifactDigest: helper.config.Identity.ArtifactDigest, ManifestDigest: verified.ManifestDigest,
		Operation: NativeOperationName, RequiredTier: "T0", Target: request.Target,
		MappingID: request.Mapping.MappingID, MappingRevision: request.Mapping.Revision, Inputs: inputs}
	executionCtx, cancel := context.WithDeadline(ctx, deadline)
	result, runErr := helper.runner.ExecuteSigmaNative(executionCtx, call)
	executionErr := executionCtx.Err()
	cancel()
	if runErr != nil {
		if errors.Is(executionErr, context.DeadlineExceeded) {
			return CompileResponse{}, nativeError(queryconnector.Timeout, "pysigma_timeout", executionErr)
		}
		if errors.Is(executionErr, context.Canceled) {
			return CompileResponse{}, nativeError(queryconnector.Canceled, "pysigma_canceled", executionErr)
		}
		return CompileResponse{}, nativeError(queryconnector.Unavailable, "pysigma_execution", runErr)
	}
	if err := nativeContextError(ctx); err != nil {
		return CompileResponse{}, err
	}
	if !validNativeExecution(call, result) {
		return CompileResponse{}, nativeError(queryconnector.Denied, "pysigma_execution_binding", nil)
	}
	response, err := DecodeCompileResponse(result.StandardOutput)
	if err != nil || ValidateExchange(request, response) != nil {
		return CompileResponse{}, nativeError(queryconnector.Denied, "pysigma_response_contract", err)
	}
	return response, nil
}

func validNativeExecution(call NativeCall, result NativeExecution) bool {
	return result.AttemptID == call.AttemptID && result.ToolName == call.ToolName &&
		result.ToolVersion == call.ToolVersion && result.ArtifactDigest == call.ArtifactDigest &&
		result.ManifestDigest == call.ManifestDigest && result.Operation == call.Operation &&
		result.RequiredTier == call.RequiredTier && result.Target == call.Target &&
		result.MappingID == call.MappingID && result.MappingRevision == call.MappingRevision &&
		result.Outcome == "succeeded" && !result.OutputTruncated && len(result.StandardError) == 0 &&
		len(result.StandardOutput) > 0 && len(result.StandardOutput) <= MaximumDocumentBytes
}

func splitNativeUTF8(input []byte) ([][]byte, error) {
	if len(input) == 0 || len(input) > maximumChunkCount*maximumChunkBytes || !utf8.Valid(input) {
		return nil, nativeError(queryconnector.InvalidInput, "pysigma_request_transport", nil)
	}
	chunks := make([][]byte, 0, (len(input)+maximumChunkBytes-1)/maximumChunkBytes)
	for len(input) > 0 {
		end := min(len(input), maximumChunkBytes)
		for end > 0 && !utf8.Valid(input[:end]) {
			end--
		}
		if end == 0 {
			return nil, nativeError(queryconnector.InvalidInput, "pysigma_request_transport", nil)
		}
		chunks = append(chunks, append([]byte(nil), input[:end]...))
		input = input[end:]
	}
	return chunks, nil
}

func nativeContextError(ctx context.Context) error {
	if ctx == nil {
		return nativeError(queryconnector.InvalidInput, "pysigma_context_required", nil)
	}
	if err := ctx.Err(); errors.Is(err, context.DeadlineExceeded) {
		return nativeError(queryconnector.Timeout, "pysigma_timeout", err)
	} else if err != nil {
		return nativeError(queryconnector.Canceled, "pysigma_canceled", err)
	}
	return nil
}

func nativeError(code queryconnector.ErrorCode, reason string, cause error) error {
	return queryconnector.NewError(code, reason, cause)
}
