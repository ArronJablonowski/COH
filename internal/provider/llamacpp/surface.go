package llamacpp

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
	VendorSurfaceVersion = "llama.cpp.server.chat-completions/5d5cb4c"
	LlamaCPPEndpoint     = "http://127.0.0.1:8080"
	HealthPath           = "/health"
	PropertiesPath       = "/props"
	ModelsPath           = "/v1/models"
	ChatPath             = "/v1/chat/completions"
	maximumRequestBytes  = 2 << 20
	maximumResponseBytes = 8 << 20
	endpointDigestDomain = "COH-LLAMACPP-ENDPOINT-V1\x00"
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
	Endpoint              string
	BuildInfo             string
	ExpectedRuntimeDigest string
	ModelAlias            string
	ModelPath             string
	ExpectedGGUFDigest    string
	ChatTemplateDigest    string
}

// LocalRouteVerifier is supplied by the managed deployment boundary. It must
// independently hash the selected llama-server binary and GGUF file, attest
// the exact launch configuration, and reject router, agent, MCP, remote-media,
// mutable properties, or non-loopback serving modes.
type LocalRouteVerifier interface {
	VerifyLocal(context.Context, LocalRouteObservation) error
}

// ReasoningStore retains model reasoning behind a digest-addressed reference.
// It is local COH state, not provider-managed conversation state.
type ReasoningStore interface {
	Put(context.Context, string, string, []byte) error
	Resolve(context.Context, string, string) ([]byte, error)
}

func EndpointIdentityDigest(endpoint string) string {
	input := endpointDigestDomain + endpoint + HealthPath + "\x00" + PropertiesPath + "\x00" + ModelsPath + "\x00" + ChatPath
	sum := sha256.Sum256([]byte(input))
	return "sha256:" + hex.EncodeToString(sum[:])
}
