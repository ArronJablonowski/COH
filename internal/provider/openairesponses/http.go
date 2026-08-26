package openairesponses

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func NewSecureHTTPClient(timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 || timeout > 24*time.Hour {
		return nil, newError(providercontract.InvalidInput, "http_timeout", false)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.openai.com"}
	client := &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, nil
}

func (adapter *Adapter) post(ctx context.Context, payload createRequest) ([]byte, error) {
	response, err := adapter.startRequest(ctx, payload, false)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		return nil, newError(providercontract.Unavailable, "response_read_failed", true)
	}
	if len(responseBody) > maximumResponseBytes {
		return nil, newError(providercontract.Denied, "response_too_large", false)
	}
	return responseBody, nil
}

func (adapter *Adapter) startRequest(ctx context.Context, payload createRequest, stream bool) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil || len(body) == 0 || len(body) > maximumRequestBytes {
		return nil, newError(providercontract.InvalidInput, "request_size", false)
	}
	credential, err := adapter.config.Credentials.Resolve(ctx, adapter.config.CredentialReference)
	if err != nil {
		return nil, newError(providercontract.Unavailable, "credential_resolution_failed", false)
	}
	defer credential.destroy()
	if !validCredential(credential.value) {
		return nil, newError(providercontract.Denied, "credential_invalid", false)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, adapter.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, newError(providercontract.Internal, "request_construction", false)
	}
	request.Header.Set("Authorization", "Bearer "+string(credential.value))
	request.Header.Set("Content-Type", "application/json")
	accept := "application/json"
	if stream {
		accept = "text/event-stream"
	}
	request.Header.Set("Accept", accept)
	response, err := adapter.config.HTTP.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextAdapterError(ctx.Err())
		}
		return nil, newError(providercontract.Unavailable, "transport_unavailable", true)
	}
	if response == nil || response.Body == nil {
		return nil, newError(providercontract.Unavailable, "transport_response_missing", true)
	}
	if response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version < tls.VersionTLS12 ||
		response.TLS.ServerName != "api.openai.com" || response.Request == nil ||
		response.Request.Method != http.MethodPost || response.Request.URL.String() != adapter.config.Endpoint {
		response.Body.Close()
		return nil, newError(providercontract.Denied, "transport_identity_invalid", false)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, statusError(response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != accept {
		response.Body.Close()
		return nil, newError(providercontract.Denied, "response_content_type", false)
	}
	return response, nil
}

func validCredential(value []byte) bool {
	if len(value) < 16 || len(value) > 4096 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return !strings.HasPrefix(strings.ToLower(string(value)), "bearer")
}

func statusError(status int) error {
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return newError(providercontract.InvalidInput, "vendor_rejected_request", false)
	case http.StatusUnauthorized, http.StatusForbidden:
		return newError(providercontract.Denied, "vendor_authentication_denied", false)
	case http.StatusNotFound:
		return newError(providercontract.Unsupported, "vendor_resource_not_found", false)
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return newError(providercontract.Timeout, "vendor_timeout", true)
	case http.StatusConflict:
		return newError(providercontract.Conflict, "vendor_conflict", false)
	case http.StatusTooManyRequests:
		return newError(providercontract.Unavailable, "vendor_rate_limited", true)
	default:
		if status >= 500 && status <= 599 {
			return newError(providercontract.Unavailable, "vendor_unavailable", true)
		}
		return newError(providercontract.Unavailable, "vendor_status_unexpected", false)
	}
}
