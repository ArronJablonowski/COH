package ollama

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
	AdapterVersion       = "1.2.0"
	VendorSurfaceVersion = "ollama.native.chat/v3"
	OllamaEndpoint       = "http://127.0.0.1:11434"
	VersionPath          = "/api/version"
	TagsPath             = "/api/tags"
	ShowPath             = "/api/show"
	ChatPath             = "/api/chat"
	maximumRequestBytes  = 2 << 20
	maximumResponseBytes = 8 << 20
	endpointDigestDomain = "COH-OLLAMA-NATIVE-ENDPOINT-V1\x00"
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
	// DisableReasoning is set only when the bound model does not advertise
	// Ollama's native thinking capability. The default remains enabled.
	DisableReasoning bool
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
	Endpoint       string
	RuntimeVersion string
	Model          string
	ModelRevision  string
}

// LocalIdentityObservation is an immutable runtime/model tuple discovered
// from the loopback-native Ollama surface before capability qualification.
type LocalIdentityObservation struct {
	Provider     providercontract.ProviderIdentity
	Capabilities []string
}

// LocalRouteVerifier is supplied by the managed deployment boundary. It must
// attest that the observed Ollama process is cloud-disabled and cannot proxy
// the selected model outside the qualified local route.
type LocalRouteVerifier interface {
	VerifyLocal(context.Context, LocalRouteObservation) error
}

// ReasoningStore retains model thinking behind a digest-addressed reference.
// It is local COH state, not provider-managed conversation state.
type ReasoningStore interface {
	Put(context.Context, string, string, []byte) error
	Resolve(context.Context, string, string) ([]byte, error)
}

func EndpointIdentityDigest(endpoint string) string {
	input := endpointDigestDomain + endpoint + VersionPath + "\x00" + TagsPath + "\x00" + ShowPath + "\x00" + ChatPath
	sum := sha256.Sum256([]byte(input))
	return "sha256:" + hex.EncodeToString(sum[:])
}
