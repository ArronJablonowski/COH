package elastic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const maximumCredentialBytes = 8192

type HTTPClient struct {
	config      Config
	endpoint    *url.URL
	credentials CredentialSource
	client      *http.Client
}

func NewHTTPClient(config Config, credentials CredentialSource, roots *x509.CertPool) (*HTTPClient, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if nilPort(credentials) {
		return nil, invalid("elastic_credential_source_required")
	}
	endpoint, _ := url.Parse(config.Endpoint)
	tlsConfig := &tls.Config{ // #nosec G402 -- TLS 1.3 and normal chain verification are mandatory.
		MinVersion: tls.VersionTLS13,
		ServerName: endpoint.Hostname(),
		RootCAs:    roots,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		MaxConnsPerHost:       1,
		ResponseHeaderTimeout: time.Duration(config.HardLimits.MaximumDurationMillis) * time.Millisecond,
	}
	client := &http.Client{Transport: transport,
		Timeout:       time.Duration(config.HardLimits.MaximumDurationMillis) * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("elastic redirects denied") },
	}
	return &HTTPClient{config: cloneConfig(config), endpoint: endpoint, credentials: credentials, client: client}, nil
}

func (client *HTTPClient) Inspect(ctx context.Context, binding CallBinding) (ClusterIdentity, CallReceipt, error) {
	if err := validateHTTPBinding(binding, "elastic.inspect", binding.Scope.ResourceIDs); err != nil {
		return ClusterIdentity{}, CallReceipt{}, err
	}
	body, receipt, err := client.do(ctx, binding, http.MethodGet, "/", nil, nil)
	if err != nil {
		return ClusterIdentity{}, CallReceipt{}, err
	}
	var response struct {
		ClusterUUID string `json:"cluster_uuid"`
		Version     struct {
			Number      string `json:"number"`
			BuildFlavor string `json:"build_flavor"`
			BuildHash   any    `json:"build_hash"`
			Snapshot    bool   `json:"build_snapshot"`
		} `json:"version"`
	}
	if err := decodeVendor(body, &response); err != nil || response.ClusterUUID == "" || response.Version.Number == "" {
		return ClusterIdentity{}, CallReceipt{}, denied("elastic_identity_response_invalid")
	}
	return ClusterIdentity{ClusterUUID: response.ClusterUUID, Version: response.Version.Number,
		BuildFlavor: response.Version.BuildFlavor, BuildHash: fmt.Sprint(response.Version.BuildHash),
		Snapshot: response.Version.Snapshot}, receipt, nil
}

func (client *HTTPClient) Resolve(ctx context.Context, request ResolveRequest) (ResolveResult, CallReceipt, error) {
	if request.Expand != "open" || !validExpression(request.Expression) {
		return ResolveResult{}, CallReceipt{}, invalid("elastic_resolve_request_invalid")
	}
	if err := validateHTTPBinding(request.Binding, "elastic.resolve", request.Binding.Targets); err != nil || len(request.Binding.Targets) != 1 {
		return ResolveResult{}, CallReceipt{}, denied("elastic_resolve_binding_invalid")
	}
	query := url.Values{"expand_wildcards": []string{"open"}}
	requestPath := "/_resolve/index/" + request.Expression
	escapedPath := "/_resolve/index/" + url.PathEscape(request.Expression)
	body, receipt, err := client.doEscaped(ctx, request.Binding, http.MethodGet, requestPath, escapedPath, query, nil)
	if err != nil {
		return ResolveResult{}, CallReceipt{}, err
	}
	var response struct {
		Indices []struct {
			Name       string   `json:"name"`
			Attributes []string `json:"attributes"`
		} `json:"indices"`
		Aliases []struct {
			Name    string   `json:"name"`
			Indices []string `json:"indices"`
		} `json:"aliases"`
		DataStreams []struct {
			Name           string   `json:"name"`
			BackingIndices []string `json:"backing_indices"`
		} `json:"data_streams"`
	}
	if err := decodeVendor(body, &response); err != nil {
		return ResolveResult{}, CallReceipt{}, denied("elastic_resolve_response_invalid")
	}
	result := ResolveResult{Indices: make([]ResolvedTarget, len(response.Indices)),
		Aliases: make([]ResolvedAlias, len(response.Aliases)), DataStreams: make([]ResolvedDataStream, len(response.DataStreams))}
	for index, value := range response.Indices {
		result.Indices[index] = ResolvedTarget{Name: value.Name, Attributes: value.Attributes}
	}
	for index, value := range response.Aliases {
		result.Aliases[index] = ResolvedAlias{Name: value.Name, Indices: value.Indices}
	}
	for index, value := range response.DataStreams {
		result.DataStreams[index] = ResolvedDataStream{Name: value.Name, BackingIndices: value.BackingIndices}
	}
	return result, receipt, nil
}

func (client *HTTPClient) FieldCapabilities(ctx context.Context, request FieldCapabilitiesRequest) (FieldCapabilitiesResult, CallReceipt, error) {
	if len(request.Indices) == 0 || len(request.Indices) > maximumResources || len(request.Fields) == 0 ||
		len(request.Fields) > maximumFields || request.AllowNoIndices || request.IgnoreUnavailable ||
		request.ExpandWildcards != "open" || !request.IncludeUnmapped || !slices.IsSorted(request.Indices) ||
		!slices.IsSorted(request.Fields) || duplicate(request.Indices) || duplicate(request.Fields) {
		return FieldCapabilitiesResult{}, CallReceipt{}, invalid("elastic_field_caps_request_invalid")
	}
	if err := validateHTTPBinding(request.Binding, "elastic.field_caps", request.Indices); err != nil {
		return FieldCapabilitiesResult{}, CallReceipt{}, denied("elastic_field_caps_binding_invalid")
	}
	for _, index := range request.Indices {
		if !safeConcreteIndex(index) {
			return FieldCapabilitiesResult{}, CallReceipt{}, invalid("elastic_field_caps_request_invalid")
		}
	}
	for _, field := range request.Fields {
		if !vendorNamePattern.MatchString(field) || strings.Contains(field, "*") {
			return FieldCapabilitiesResult{}, CallReceipt{}, invalid("elastic_field_caps_request_invalid")
		}
	}
	payload, _ := json.Marshal(struct {
		Fields []string `json:"fields"`
	}{Fields: request.Fields})
	query := url.Values{"allow_no_indices": []string{"false"}, "ignore_unavailable": []string{"false"},
		"expand_wildcards": []string{"open"}, "include_unmapped": []string{"true"}}
	body, receipt, err := client.do(ctx, request.Binding, http.MethodPost,
		"/"+strings.Join(request.Indices, ",")+"/_field_caps", query, payload)
	if err != nil {
		return FieldCapabilitiesResult{}, CallReceipt{}, err
	}
	var response struct {
		Indices []string `json:"indices"`
		Fields  map[string]map[string]struct {
			Searchable   bool     `json:"searchable"`
			Aggregatable bool     `json:"aggregatable"`
			Indices      []string `json:"indices"`
		} `json:"fields"`
	}
	if err := decodeVendor(body, &response); err != nil || len(response.Fields) > maximumFields {
		return FieldCapabilitiesResult{}, CallReceipt{}, denied("elastic_field_caps_response_invalid")
	}
	result := FieldCapabilitiesResult{Indices: response.Indices}
	for name, types := range response.Fields {
		if len(types) == 0 || len(types) > 8 {
			return FieldCapabilitiesResult{}, CallReceipt{}, denied("elastic_field_caps_response_invalid")
		}
		for fieldType, capability := range types {
			result.Fields = append(result.Fields, FieldCapability{Name: name, Type: fieldType,
				Indices: capability.Indices, Searchable: capability.Searchable, Aggregatable: capability.Aggregatable})
		}
	}
	slices.SortFunc(result.Fields, func(left, right FieldCapability) int {
		if compared := strings.Compare(left.Name, right.Name); compared != 0 {
			return compared
		}
		return strings.Compare(left.Type, right.Type)
	})
	return result, receipt, nil
}

func (client *HTTPClient) do(ctx context.Context, binding CallBinding, method, requestPath string, query url.Values, payload []byte) ([]byte, CallReceipt, error) {
	return client.doEscaped(ctx, binding, method, requestPath, "", query, payload)
}

func (client *HTTPClient) doEscaped(ctx context.Context, binding CallBinding, method, requestPath, escapedPath string, query url.Values, payload []byte) ([]byte, CallReceipt, error) {
	if client == nil || client.client == nil || nilPort(client.credentials) {
		return nil, CallReceipt{}, invalid("elastic_http_client_required")
	}
	if err := contextError(ctx); err != nil {
		return nil, CallReceipt{}, err
	}
	requestURL := *client.endpoint
	requestURL.Path, requestURL.RawPath, requestURL.RawQuery = requestPath, escapedPath, query.Encode()
	requestDigest := digest("COH-ELASTIC-HTTP-REQUEST-V1\x00", struct {
		Method string
		Path   string
		Query  string
		Body   []byte
	}{method, requestPath, requestURL.RawQuery, payload})
	var body []byte
	var responseDigest, transportDigest string
	decisionDigest, err := client.credentials.Use(ctx, binding, func(secret []byte) error {
		if !validCredential(secret) {
			return denied("elastic_credential_invalid")
		}
		request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(payload))
		if err != nil {
			return invalid("elastic_http_request_invalid")
		}
		request.Header.Set("Accept", "application/json")
		if len(payload) != 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		request.Header.Set("Authorization", "ApiKey "+string(secret))
		defer request.Header.Del("Authorization")
		response, err := client.client.Do(request)
		if err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return contextErr
			}
			return queryconnector.NewError(queryconnector.Unavailable, "elastic_transport_failed", nil)
		}
		defer response.Body.Close()
		if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
			return denied("elastic_tls_identity_missing")
		}
		spki := sha256.Sum256(response.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
		transportDigest = "sha256:" + hex.EncodeToString(spki[:])
		if transportDigest != client.config.TransportIdentityDigest {
			return conflict("elastic_tls_identity_mismatch")
		}
		maximum := int64(client.config.HardLimits.MaximumBytes)
		if maximum > queryconnector.MaximumDocumentBytes {
			maximum = queryconnector.MaximumDocumentBytes
		}
		body, err = io.ReadAll(io.LimitReader(response.Body, maximum+1))
		if err != nil || int64(len(body)) > maximum {
			return denied("elastic_response_oversized")
		}
		responseDigest = digest("COH-ELASTIC-HTTP-RESPONSE-V1\x00", struct {
			Status int
			Body   []byte
		}{response.StatusCode, body})
		if response.StatusCode != http.StatusOK {
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
				return denied("elastic_authentication_or_privilege_denied")
			}
			return queryconnector.NewError(queryconnector.Unavailable, "elastic_vendor_unavailable", nil)
		}
		return nil
	})
	if err != nil {
		return nil, CallReceipt{}, mapClientError(err)
	}
	if !digestPattern.MatchString(decisionDigest) {
		return nil, CallReceipt{}, denied("elastic_lease_receipt_invalid")
	}
	return body, CallReceipt{RequestDigest: requestDigest, ResponseDigest: responseDigest,
		LeaseDecisionDigest: decisionDigest, TransportDigest: transportDigest}, nil
}

func decodeVendor(input []byte, output any) error {
	if len(input) == 0 || !json.Valid(input) {
		return errors.New("invalid vendor JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing vendor JSON")
	}
	return nil
}

func validCredential(secret []byte) bool {
	if len(secret) == 0 || len(secret) > maximumCredentialBytes {
		return false
	}
	for _, value := range secret {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

func validateHTTPBinding(binding CallBinding, operation string, targets []string) error {
	if err := validateBinding(binding.Scope, binding.Authority); err != nil || binding.Operation != operation ||
		len(targets) == 0 || !slices.Equal(binding.Targets, targets) {
		return denied("elastic_call_binding_invalid")
	}
	for _, target := range targets {
		if strings.TrimSpace(target) == "" || len(target) > 255 {
			return denied("elastic_call_binding_invalid")
		}
	}
	return nil
}
