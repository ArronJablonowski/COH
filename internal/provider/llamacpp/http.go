package llamacpp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func NewLoopbackHTTPClient(timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 || timeout > 24*time.Hour {
		return nil, newError(providercontract.InvalidInput, "http_timeout", false)
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = false
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || network != "tcp" && network != "tcp4" || host != "127.0.0.1" || port != "8080" {
			return nil, newError(providercontract.Denied, "dial_target_not_approved", false)
		}
		return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(host, port))
	}
	return &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (adapter *Adapter) getJSON(ctx context.Context, path string, output any) ([]byte, error) {
	return adapter.doJSON(ctx, http.MethodGet, path, nil, output)
}

func (adapter *Adapter) postJSON(ctx context.Context, path string, input, output any) ([]byte, error) {
	return adapter.doJSON(ctx, http.MethodPost, path, input, output)
}

func (adapter *Adapter) doJSON(ctx context.Context, method, path string, input, output any) ([]byte, error) {
	response, err := adapter.startRequest(ctx, method, path, input, "application/json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		return nil, newError(providercontract.Unavailable, "response_read_failed", true)
	}
	if len(body) > maximumResponseBytes {
		return nil, newError(providercontract.Denied, "response_too_large", false)
	}
	canonical, err := canonicalJSON(body)
	if err != nil {
		return nil, err
	}
	if err := decodeExact(canonical, output); err != nil {
		return nil, err
	}
	return canonical, nil
}

func (adapter *Adapter) startRequest(ctx context.Context, method, path string, input any, accept string) (*http.Response, error) {
	if !allowedOperation(method, path) {
		return nil, newError(providercontract.Denied, "operation_not_approved", false)
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil || len(body) == 0 || len(body) > maximumRequestBytes {
			return nil, newError(providercontract.InvalidInput, "request_size", false)
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, adapter.config.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, newError(providercontract.Internal, "request_construction", false)
	}
	request.Header.Set("Accept", accept)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("X-API-Key") != "" || request.URL.User != nil {
		return nil, newError(providercontract.Denied, "ambient_credential", false)
	}
	response, err := adapter.config.HTTP.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextAdapterError(ctx.Err())
		}
		return nil, newError(providercontract.Unavailable, "transport_unavailable", true)
	}
	if response == nil || response.Body == nil {
		return nil, newError(providercontract.Unavailable, "transport_response_missing", true)
	}
	if response.TLS != nil || response.Request == nil || response.Request.Method != method ||
		response.Request.URL.String() != adapter.config.Endpoint+path || response.Request.Header.Get("Authorization") != "" ||
		response.Request.Header.Get("X-API-Key") != "" {
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

func allowedOperation(method, path string) bool {
	return method == http.MethodGet && (path == HealthPath || path == PropertiesPath || path == ModelsPath) ||
		method == http.MethodPost && path == ChatPath
}

func statusError(status int) error {
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return newError(providercontract.InvalidInput, "vendor_rejected_request", false)
	case http.StatusUnauthorized, http.StatusForbidden:
		return newError(providercontract.Denied, "vendor_access_denied", false)
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
		return newError(providercontract.Unavailable, "vendor_status_"+strconv.Itoa(status), false)
	}
}
