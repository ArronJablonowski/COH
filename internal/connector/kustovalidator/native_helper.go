package kustovalidator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

const maximumChunkBytes = 61_440

// NativeCall is an authority-neutral request for the broker-owned native
// runner. The broker supplies current dispatch authority; this value cannot.
type NativeCall struct {
	AttemptID      string
	ToolName       string
	ToolVersion    string
	ArtifactDigest string
	ManifestDigest string
	Operation      string
	RequiredTier   string
	Inputs         map[string]string
}

type NativeExecution struct {
	AttemptID       string
	ToolName        string
	ToolVersion     string
	ArtifactDigest  string
	ManifestDigest  string
	Operation       string
	RequiredTier    string
	Outcome         string
	StandardOutput  []byte
	StandardError   []byte
	OutputTruncated bool
}

type NativeRunner interface {
	ExecuteKustoNative(context.Context, NativeCall) (NativeExecution, error)
}

type NativeConfiguration struct {
	ToolName       string
	ToolVersion    string
	ArtifactDigest string
	ManifestDigest string
}

type NativeHelper struct {
	runner NativeRunner
	config NativeConfiguration
}

func NewNativeHelper(runner NativeRunner, config NativeConfiguration) (*NativeHelper, error) {
	if runner == nil || config.ToolName != NativeToolName || config.ToolVersion != NativeToolVersion ||
		!validDigests(config.ArtifactDigest, config.ManifestDigest) {
		return nil, errors.New("kusto native helper configuration denied")
	}
	return &NativeHelper{runner: runner, config: config}, nil
}

func (helper *NativeHelper) Validate(ctx context.Context, request HelperRequest) (HelperResponse, error) {
	if helper == nil || helper.runner == nil {
		return HelperResponse{}, errors.New("kusto native helper unavailable")
	}
	if validateHelperRequest(request) != nil || request.HelperIdentityExpectation.ArtifactDigest != helper.config.ArtifactDigest {
		return HelperResponse{}, errors.New("kusto native artifact binding denied")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return HelperResponse{}, errors.New("kusto native request encoding denied")
	}
	chunks, err := splitUTF8(encoded)
	if err != nil {
		return HelperResponse{}, err
	}
	inputs := make(map[string]string, len(chunks))
	for index, chunk := range chunks {
		inputs[fmt.Sprintf("request_chunk_%02d", index)] = string(chunk)
	}
	call := NativeCall{AttemptID: request.RequestID, ToolName: helper.config.ToolName,
		ToolVersion: helper.config.ToolVersion, ArtifactDigest: helper.config.ArtifactDigest,
		ManifestDigest: helper.config.ManifestDigest, Operation: NativeOperationName, RequiredTier: "T0", Inputs: inputs}
	result, err := helper.runner.ExecuteKustoNative(ctx, call)
	if err != nil {
		return HelperResponse{}, err
	}
	if result.AttemptID != call.AttemptID || result.ToolName != call.ToolName || result.ToolVersion != call.ToolVersion ||
		result.ArtifactDigest != call.ArtifactDigest || result.ManifestDigest != call.ManifestDigest ||
		result.Operation != call.Operation || result.RequiredTier != call.RequiredTier || result.Outcome != "succeeded" ||
		result.OutputTruncated || len(result.StandardError) != 0 {
		return HelperResponse{}, errors.New("kusto native provenance binding denied")
	}
	response, err := DecodeHelperResponse(result.StandardOutput)
	if err != nil {
		return HelperResponse{}, errors.New("kusto native response denied")
	}
	if ValidateHelperExchange(request, response) != nil {
		return HelperResponse{}, errors.New("kusto native exchange denied")
	}
	return response, nil
}

func splitUTF8(input []byte) ([][]byte, error) {
	if len(input) == 0 || len(input) > 8*maximumChunkBytes || !utf8.Valid(input) {
		return nil, errors.New("kusto native request exceeds transport")
	}
	chunks := make([][]byte, 0, (len(input)+maximumChunkBytes-1)/maximumChunkBytes)
	for len(input) > 0 {
		end := min(len(input), maximumChunkBytes)
		for end > 0 && !utf8.Valid(input[:end]) {
			end--
		}
		if end == 0 {
			return nil, errors.New("kusto native UTF-8 chunking denied")
		}
		chunks = append(chunks, append([]byte(nil), input[:end]...))
		input = input[end:]
	}
	return chunks, nil
}
