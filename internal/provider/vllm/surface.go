package vllm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	AdapterVersion       = "1.0.0"
	VendorSurfaceVersion = "vllm.openai.chat-completions/796822d"
	VLLMEndpoint         = "http://127.0.0.1:8000"
	HealthPath           = "/health"
	VersionPath          = "/version"
	ModelsPath           = "/v1/models"
	TokenizerInfoPath    = "/tokenizer_info"
	ChatPath             = "/v1/chat/completions"
	maximumRequestBytes  = 2 << 20
	maximumResponseBytes = 8 << 20
	endpointDigestDomain = "COH-VLLM-ENDPOINT-V1\x00"
)

type Config struct {
	Endpoint       string
	Capability     providercontract.ValidatedCapability
	Qualifications *providercontract.QualificationRegistry
	Schemas        SchemaResolver
	Reasoning      ReasoningStore
	Tokens         TokenCounter
	Route          LocalRouteVerifier
	HTTP           HTTPDoer
	Clock          func() time.Time
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type SchemaDocument struct {
	Digest string
	JSON   json.RawMessage
}
type SchemaResolver interface {
	Resolve(context.Context, string) (SchemaDocument, error)
}
type TokenCounter interface {
	Count(context.Context, providercontract.ValidatedRequest) (uint64, error)
}

type LocalRouteObservation struct {
	Endpoint                      string
	RuntimeVersion                string
	ExpectedRuntimeDigest         string
	ExpectedImageDigest           string
	ModelAlias                    string
	ModelRoot                     string
	ExpectedModelWeightsDigest    string
	TokenizerDigest               string
	ChatTemplateDigest            string
	ExpectedToolParserDigest      string
	ExpectedReasoningParserDigest string
	ExpectedHardwareProfileDigest string
	ExpectedLaunchProfileDigest   string
	RequiredStateMode             string
}

// LocalRouteVerifier independently attests facts the provider-controlled HTTP
// surface cannot prove: package/image and model digests, CUDA/PyTorch/GPU
// topology, exact parser implementations and launch flags, disabled dev and
// mutation surfaces, and stateless operation.
type LocalRouteVerifier interface {
	VerifyLocal(context.Context, LocalRouteObservation) error
}

type ReasoningStore interface {
	Put(context.Context, string, string, []byte) error
	Resolve(context.Context, string, string) ([]byte, error)
}

func EndpointIdentityDigest(endpoint string) string {
	input := endpointDigestDomain + endpoint + HealthPath + "\x00" + VersionPath + "\x00" + ModelsPath + "\x00" + TokenizerInfoPath + "\x00" + ChatPath
	sum := sha256.Sum256([]byte(input))
	return "sha256:" + hex.EncodeToString(sum[:])
}
