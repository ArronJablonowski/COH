package splunk

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
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumCredentialBytes = 8192

type HTTPClient struct {
	config      Config
	endpoint    *url.URL
	credentials CredentialSource
	tlsConfig   *tls.Config
	client      *http.Client
}

func NewHTTPClient(config Config, credentials CredentialSource, roots *x509.CertPool) (*HTTPClient, error) {
	if err := validateConfig(config); err != nil {
		return nil, invalidInput("splunk_http_configuration_invalid")
	}
	if nilPort(credentials) || roots == nil {
		return nil, invalidInput("splunk_http_configuration_invalid")
	}
	endpoint, _ := url.Parse(config.Endpoint)
	tlsConfig := &tls.Config{ // #nosec G402 -- TLS 1.3 and normal chain verification are mandatory.
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: endpoint.Hostname()}
	duration := time.Duration(config.HardLimits.MaximumDurationMillis) * time.Millisecond
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		MaxIdleConns: 0, MaxConnsPerHost: 1, ResponseHeaderTimeout: duration, TLSClientConfig: tlsConfig.Clone()}
	httpClient := &http.Client{Transport: transport, Timeout: duration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("splunk redirects denied") }}
	return &HTTPClient{config: cloneConfig(config), endpoint: endpoint, credentials: credentials,
		tlsConfig: tlsConfig, client: httpClient}, nil
}

func (client *HTTPClient) ServerInfo(ctx context.Context, binding CallBinding) (ServerIdentity, CallReceipt, error) {
	if err := validateCallBinding(client.config, binding, "splunk.server_info"); err != nil {
		return ServerIdentity{}, CallReceipt{}, err
	}
	body, receipt, err := client.get(ctx, binding, "/services/server/info", url.Values{"count": {"1"}, "output_mode": {"json"}})
	if err != nil {
		return ServerIdentity{}, CallReceipt{}, err
	}
	var response splunkEntries[struct {
		GUID        string   `json:"guid"`
		ProductType string   `json:"product_type"`
		Version     string   `json:"version"`
		Build       string   `json:"build"`
		ServerRoles []string `json:"server_roles"`
	}]
	if err := decodeVendor(body, &response); err != nil || len(response.Entry) != 1 {
		return ServerIdentity{}, CallReceipt{}, deniedCall("splunk_server_info_response_invalid")
	}
	value := response.Entry[0].Content
	slices.Sort(value.ServerRoles)
	if !guidPattern.MatchString(value.GUID) || value.ProductType == "" || !versionPattern.MatchString(value.Version) ||
		!buildPattern.MatchString(value.Build) || !validNames(value.ServerRoles, 1, 16) {
		return ServerIdentity{}, CallReceipt{}, deniedCall("splunk_server_info_response_invalid")
	}
	return ServerIdentity{GUID: value.GUID, ProductType: value.ProductType, Version: value.Version,
		Build: value.Build, ServerRoles: append([]string(nil), value.ServerRoles...)}, receipt, nil
}

func (client *HTTPClient) CurrentContext(ctx context.Context, binding CallBinding) (CurrentContext, CallReceipt, error) {
	if err := validateCallBinding(client.config, binding, "splunk.current_context"); err != nil {
		return CurrentContext{}, CallReceipt{}, err
	}
	body, receipt, err := client.get(ctx, binding, "/services/authentication/current-context",
		url.Values{"count": {"1"}, "output_mode": {"json"}})
	if err != nil {
		return CurrentContext{}, CallReceipt{}, err
	}
	var response splunkEntries[struct {
		Capabilities []string `json:"capabilities"`
	}]
	if err := decodeVendor(body, &response); err != nil || len(response.Entry) != 1 {
		return CurrentContext{}, CallReceipt{}, deniedCall("splunk_current_context_response_invalid")
	}
	capabilities := append([]string(nil), response.Entry[0].Content.Capabilities...)
	slices.Sort(capabilities)
	if !validNames(capabilities, 1, 256) {
		return CurrentContext{}, CallReceipt{}, deniedCall("splunk_current_context_response_invalid")
	}
	return CurrentContext{Capabilities: capabilities}, receipt, nil
}

func (client *HTTPClient) Indexes(ctx context.Context, request InventoryRequest) (IndexInventory, CallReceipt, error) {
	if err := validateInventoryRequest(client.config, request, "splunk.indexes"); err != nil {
		return IndexInventory{}, CallReceipt{}, err
	}
	query := inventoryQuery(request.MaximumEntries)
	query.Set("summarize", "true")
	body, receipt, err := client.get(ctx, request.Binding, "/services/data/indexes", query)
	if err != nil {
		return IndexInventory{}, CallReceipt{}, err
	}
	var response splunkEntries[struct{}]
	if err := decodeVendor(body, &response); err != nil || len(response.Entry) > request.MaximumEntries+1 {
		return IndexInventory{}, CallReceipt{}, deniedCall("splunk_index_inventory_response_invalid")
	}
	names := make([]string, 0, len(response.Entry))
	for _, entry := range response.Entry {
		if !safeIndex(entry.Name) {
			return IndexInventory{}, CallReceipt{}, deniedCall("splunk_index_inventory_response_invalid")
		}
		names = append(names, entry.Name)
	}
	slices.Sort(names)
	if duplicateValues(names) {
		return IndexInventory{}, CallReceipt{}, deniedCall("splunk_index_inventory_response_invalid")
	}
	truncated := len(names) > request.MaximumEntries
	if truncated {
		names = names[:request.MaximumEntries]
	}
	return IndexInventory{Names: names, Truncated: truncated}, receipt, nil
}

func (client *HTTPClient) RegisteredFields(ctx context.Context, request InventoryRequest) (RegisteredFieldInventory, CallReceipt, error) {
	if err := validateInventoryRequest(client.config, request, "splunk.fields"); err != nil {
		return RegisteredFieldInventory{}, CallReceipt{}, err
	}
	body, receipt, err := client.get(ctx, request.Binding, "/servicesNS/nobody/search/search/fields", inventoryQuery(request.MaximumEntries))
	if err != nil {
		return RegisteredFieldInventory{}, CallReceipt{}, err
	}
	var response splunkEntries[struct {
		Indexed bool `json:"indexed"`
	}]
	if err := decodeVendor(body, &response); err != nil || len(response.Entry) > request.MaximumEntries+1 {
		return RegisteredFieldInventory{}, CallReceipt{}, deniedCall("splunk_field_inventory_response_invalid")
	}
	fields := make([]RegisteredField, 0, len(response.Entry))
	for _, entry := range response.Entry {
		if !vendorFieldPattern.MatchString(entry.Name) {
			return RegisteredFieldInventory{}, CallReceipt{}, deniedCall("splunk_field_inventory_response_invalid")
		}
		fields = append(fields, RegisteredField{Name: entry.Name, Indexed: entry.Content.Indexed})
	}
	slices.SortFunc(fields, func(left, right RegisteredField) int { return strings.Compare(left.Name, right.Name) })
	if duplicateFields(fields) {
		return RegisteredFieldInventory{}, CallReceipt{}, deniedCall("splunk_field_inventory_response_invalid")
	}
	truncated := len(fields) > request.MaximumEntries
	if truncated {
		fields = fields[:request.MaximumEntries]
	}
	return RegisteredFieldInventory{Fields: fields, Truncated: truncated}, receipt, nil
}

type splunkEntries[T any] struct {
	Entry []struct {
		Name    string `json:"name"`
		Content T      `json:"content"`
	} `json:"entry"`
}

func inventoryQuery(maximum int) url.Values {
	return url.Values{"count": {strconv.Itoa(maximum + 1)}, "offset": {"0"}, "output_mode": {"json"}}
}

func (client *HTTPClient) get(ctx context.Context, binding CallBinding, path string, query url.Values) ([]byte, CallReceipt, error) {
	if client == nil || client.client == nil || nilPort(client.credentials) {
		return nil, CallReceipt{}, invalidInput("splunk_http_client_required")
	}
	if err := contextError(ctx); err != nil {
		return nil, CallReceipt{}, err
	}
	preflightDigest, err := client.verifyPeer(ctx)
	if err != nil {
		return nil, CallReceipt{}, mapTransportError(ctx, err)
	}
	requestURL := *client.endpoint
	requestURL.Path, requestURL.RawQuery = path, query.Encode()
	requestDigest := hashValue("COH-SPLUNK-HTTP-REQUEST-V1\x00", struct{ Method, Path, Query string }{http.MethodGet, path, requestURL.RawQuery})
	var body []byte
	var responseDigest, authenticatedDigest string
	decisionDigest, err := client.credentials.Use(ctx, binding, func(token []byte) error {
		if !validCredential(token) {
			return deniedCall("splunk_credential_invalid")
		}
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if requestErr != nil {
			return invalidInput("splunk_http_request_invalid")
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Authorization", "Splunk "+string(token))
		defer request.Header.Del("Authorization")
		response, requestErr := client.client.Do(request)
		if requestErr != nil {
			return mapTransportError(ctx, requestErr)
		}
		defer response.Body.Close()
		authenticatedDigest, requestErr = pinnedPeerDigest(response, client.config.TransportIdentityDigest)
		if requestErr != nil {
			return requestErr
		}
		maximum := int64(client.config.HardLimits.MaximumBytes)
		if maximum > queryconnector.MaximumDocumentBytes {
			maximum = queryconnector.MaximumDocumentBytes
		}
		body, requestErr = io.ReadAll(io.LimitReader(response.Body, maximum+1))
		if requestErr != nil || int64(len(body)) > maximum {
			return deniedCall("splunk_response_oversized")
		}
		responseDigest = hashValue("COH-SPLUNK-HTTP-RESPONSE-V1\x00", struct {
			Status int
			Body   []byte
		}{response.StatusCode, body})
		if response.StatusCode != http.StatusOK {
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
				return deniedCall("splunk_authentication_or_privilege_denied")
			}
			return queryconnector.NewError(queryconnector.Unavailable, "splunk_vendor_unavailable", nil)
		}
		return nil
	})
	if err != nil {
		return nil, CallReceipt{}, mapTransportError(ctx, err)
	}
	if !digestPattern.MatchString(decisionDigest) || authenticatedDigest != preflightDigest {
		return nil, CallReceipt{}, deniedCall("splunk_transport_receipt_invalid")
	}
	return body, CallReceipt{RequestDigest: requestDigest, ResponseDigest: responseDigest,
		LeaseDecisionDigest: decisionDigest, TransportDigest: authenticatedDigest}, nil
}

func (client *HTTPClient) verifyPeer(ctx context.Context) (string, error) {
	host := client.endpoint.Host
	if client.endpoint.Port() == "" {
		host = net.JoinHostPort(client.endpoint.Hostname(), "443")
	}
	dialer := &tls.Dialer{Config: client.tlsConfig.Clone(), NetDialer: &net.Dialer{
		Timeout: time.Duration(client.config.HardLimits.MaximumDurationMillis) * time.Millisecond}}
	connection, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return "", deniedCall("splunk_tls_identity_missing")
	}
	state := tlsConnection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", deniedCall("splunk_tls_identity_missing")
	}
	return certificateDigest(state.PeerCertificates[0], client.config.TransportIdentityDigest)
}

func pinnedPeerDigest(response *http.Response, expected string) (string, error) {
	if response == nil || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return "", deniedCall("splunk_tls_identity_missing")
	}
	return certificateDigest(response.TLS.PeerCertificates[0], expected)
}

func certificateDigest(certificate *x509.Certificate, expected string) (string, error) {
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	value := "sha256:" + hex.EncodeToString(sum[:])
	if value != expected {
		return "", conflictCall("splunk_tls_identity_mismatch")
	}
	return value, nil
}

func decodeVendor(input []byte, output any) error {
	if len(input) == 0 {
		return errors.New("empty vendor response")
	}
	unique, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(unique)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing vendor JSON")
	}
	return nil
}

func validateCallBinding(config Config, binding CallBinding, operation string) error {
	if err := validateAuthority(config, binding); err != nil || binding.Operation != operation ||
		!slices.Equal(binding.Targets, binding.Scope.ResourceIDs) {
		return deniedCall("splunk_call_binding_invalid")
	}
	return nil
}

func validateAuthority(config Config, binding CallBinding) error {
	scope, authority := binding.Scope, binding.Authority
	if !uuidV7Pattern.MatchString(scope.OrganizationID) || !uuidV7Pattern.MatchString(scope.TenantID) ||
		!uuidV7Pattern.MatchString(scope.CaseID) || !uuidV7Pattern.MatchString(authority.ActorID) ||
		scope.SourceID != config.SourceID || !validNames(scope.ResourceIDs, 1, len(config.Resources)) ||
		!validDigests(authority.AuthorizationDigest, authority.PolicyDecisionDigest, authority.AuditReservationDigest) {
		return deniedCall("splunk_authority_invalid")
	}
	allowed := make(map[string]struct{}, len(config.Resources))
	for _, resource := range config.Resources {
		allowed[resource.ID] = struct{}{}
	}
	for _, resourceID := range scope.ResourceIDs {
		if _, ok := allowed[resourceID]; !ok {
			return deniedCall("splunk_resource_not_allowed")
		}
	}
	return nil
}

func validateInventoryRequest(config Config, request InventoryRequest, operation string) error {
	if request.MaximumEntries < 1 || request.MaximumEntries > config.MaximumInventoryEntries {
		return invalidInput("splunk_inventory_request_invalid")
	}
	return validateCallBinding(config, request.Binding, operation)
}

func validCredential(value []byte) bool {
	if len(value) == 0 || len(value) > maximumCredentialBytes {
		return false
	}
	for _, item := range value {
		if item < 0x21 || item > 0x7e {
			return false
		}
	}
	return true
}

func hashValue(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(domain), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cloneConfig(value Config) Config {
	value.ExpectedServerRoles = append([]string(nil), value.ExpectedServerRoles...)
	value.QualifiedMinorVersions = append([]string(nil), value.QualifiedMinorVersions...)
	value.RequiredCapabilities = append([]string(nil), value.RequiredCapabilities...)
	value.DeniedCapabilities = append([]string(nil), value.DeniedCapabilities...)
	value.Resources = append([]Resource(nil), value.Resources...)
	value.Fields = append([]Field(nil), value.Fields...)
	for index := range value.Fields {
		value.Fields[index].ResourceIDs = append([]string(nil), value.Fields[index].ResourceIDs...)
	}
	return value
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func duplicateValues[T comparable](values []T) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func duplicateFields(values []RegisteredField) bool {
	for index := 1; index < len(values); index++ {
		if values[index].Name == values[index-1].Name {
			return true
		}
	}
	return false
}

var uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
