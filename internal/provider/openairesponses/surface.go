package openairesponses

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	AdapterVersion       = "1.0.0"
	VendorSurfaceVersion = "openai.responses.create/v1"
	ResponsesEndpoint    = "https://api.openai.com/v1/responses"
	maximumRequestBytes  = 2 << 20
	maximumResponseBytes = 8 << 20
	endpointDigestDomain = "COH-OPENAI-RESPONSES-ENDPOINT-V1\x00"
)

var referencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

type Config struct {
	Endpoint            string
	CredentialReference string
	Credentials         CredentialResolver
	Capability          providercontract.ValidatedCapability
	Qualifications      *providercontract.QualificationRegistry
	Schemas             SchemaResolver
	Reasoning           ReasoningStore
	HTTP                HTTPDoer
	Clock               func() time.Time
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Credential struct {
	value []byte
}

func NewCredential(value []byte) Credential {
	return Credential{value: append([]byte(nil), value...)}
}

func (value *Credential) destroy() {
	for index := range value.value {
		value.value[index] = 0
	}
	value.value = nil
}

type CredentialResolver interface {
	Resolve(context.Context, string) (Credential, error)
}

type SchemaDocument struct {
	Digest string
	JSON   json.RawMessage
}

type SchemaResolver interface {
	Resolve(context.Context, string) (SchemaDocument, error)
}

// ReasoningStore retains only allowlisted encrypted reasoning items. The
// adapter verifies Digest before accepting a resolved item on a later turn.
type ReasoningStore interface {
	Put(context.Context, string, string, []byte) error
	Resolve(context.Context, string, string) ([]byte, error)
}

func EndpointIdentityDigest(endpoint string) string {
	sum := sha256.Sum256(append([]byte(endpointDigestDomain), endpoint...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateConfig(config Config) error {
	if config.Endpoint != ResponsesEndpoint || !referencePattern.MatchString(config.CredentialReference) ||
		config.Credentials == nil || config.Capability.Digest() == "" || config.Qualifications == nil || config.Schemas == nil ||
		config.Reasoning == nil || config.HTTP == nil || config.Clock == nil {
		return newError(providercontract.InvalidInput, "adapter_configuration", false)
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "api.openai.com" || parsed.Path != "/v1/responses" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return newError(providercontract.Denied, "endpoint_not_approved", false)
	}
	provider := config.Capability.Value().Provider
	if provider.ProviderKind != "openai_responses" || provider.AdapterVersion != AdapterVersion ||
		provider.EndpointIdentityDigest != EndpointIdentityDigest(config.Endpoint) || provider.DataRoute != "approved_external" ||
		provider.StateMode != "stateless" {
		return newError(providercontract.Denied, "provider_identity_not_supported", false)
	}
	return nil
}
