package sentinel

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
	"mime"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumCredentialBytes = 16384

type HTTPClient struct {
	config      Config
	endpoint    *url.URL
	credentials CredentialSource
	tlsConfig   *tls.Config
	client      *http.Client
}

func NewHTTPClient(config Config, credentials CredentialSource, roots *x509.CertPool) (*HTTPClient, error) {
	if err := validateConfig(config); err != nil {
		return nil, invalidInput("sentinel_http_configuration_invalid")
	}
	return newHTTPClient(config, credentials, roots, config.Endpoint)
}

// newHTTPClient's endpoint argument exists only so package tests can terminate
// the pinned TLS session locally. Production callers use NewHTTPClient, which
// always fixes it to Config.Endpoint.
func newHTTPClient(config Config, credentials CredentialSource, roots *x509.CertPool, endpointValue string) (*HTTPClient, error) {
	if err := validateConfig(config); err != nil || nilPort(credentials) || roots == nil {
		return nil, invalidInput("sentinel_http_configuration_invalid")
	}
	endpoint, err := url.Parse(endpointValue)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return nil, invalidInput("sentinel_http_configuration_invalid")
	}
	tlsConfig := &tls.Config{ // #nosec G402 -- TLS 1.3 and normal chain verification are mandatory.
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: endpoint.Hostname()}
	duration := time.Duration(config.HardLimits.MaximumDurationMillis) * time.Millisecond
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		MaxIdleConns: 0, MaxConnsPerHost: 1, ResponseHeaderTimeout: duration, TLSClientConfig: tlsConfig.Clone()}
	httpClient := &http.Client{Transport: transport, Timeout: duration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("sentinel redirects denied") }}
	return &HTTPClient{config: cloneConfig(config), endpoint: endpoint, credentials: credentials,
		tlsConfig: tlsConfig, client: httpClient}, nil
}

func (client *HTTPClient) Metadata(ctx context.Context, request MetadataRequest) (Metadata, CallReceipt, error) {
	if client == nil || client.client == nil || nilPort(client.credentials) {
		return Metadata{}, CallReceipt{}, invalidInput("sentinel_http_client_required")
	}
	if err := validateCallBinding(client.config, request.Binding); err != nil {
		return Metadata{}, CallReceipt{}, err
	}
	if err := contextError(ctx); err != nil {
		return Metadata{}, CallReceipt{}, err
	}
	preflightDigest, err := client.verifyPeer(ctx)
	if err != nil {
		return Metadata{}, CallReceipt{}, mapTransportError(ctx, err)
	}

	path := "/" + APIVersion + "/workspaces/" + client.config.WorkspaceID + "/metadata"
	requestURL := *client.endpoint
	requestURL.Path, requestURL.RawPath, requestURL.RawQuery = path, "", ""
	requestDigest := hashValue("COH-SENTINEL-HTTP-REQUEST-V1\x00", struct {
		Method, Host, Path, Audience, Tenant string
	}{http.MethodGet, PublicEndpoint, path, client.config.TokenAudience, client.config.TenantID})
	var body []byte
	var responseDigest, authenticatedDigest string
	decisionDigest, err := client.credentials.Use(ctx, request.Binding, func(token []byte) error {
		if !validCredential(token) {
			return deniedCall("sentinel_credential_invalid")
		}
		temporary := append([]byte(nil), token...)
		defer func() {
			for index := range temporary {
				temporary[index] = 0
			}
		}()
		httpRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if requestErr != nil {
			return invalidInput("sentinel_http_request_invalid")
		}
		httpRequest.Header.Set("Accept", "application/json")
		httpRequest.Header.Set("Authorization", "Bearer "+string(temporary))
		defer httpRequest.Header.Del("Authorization")
		response, requestErr := client.client.Do(httpRequest)
		if requestErr != nil {
			return mapTransportError(ctx, requestErr)
		}
		defer response.Body.Close()
		authenticatedDigest, requestErr = pinnedPeerDigest(response, client.config.TransportIdentityDigest)
		if requestErr != nil {
			return requestErr
		}
		maximum := int64(min(client.config.MaximumMetadataBytes, uint64(queryconnector.MaximumDocumentBytes)))
		body, requestErr = io.ReadAll(io.LimitReader(response.Body, maximum+1))
		if requestErr != nil || int64(len(body)) > maximum {
			return deniedCall("sentinel_metadata_response_oversized")
		}
		responseDigest = hashValue("COH-SENTINEL-HTTP-RESPONSE-V1\x00", struct {
			Status int
			Body   []byte
		}{response.StatusCode, body})
		if response.StatusCode != http.StatusOK {
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
				return deniedCall("sentinel_authentication_or_privilege_denied")
			}
			return queryconnector.NewError(queryconnector.Unavailable, "sentinel_vendor_unavailable", nil)
		}
		mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/json" || response.Header.Get("Content-Encoding") != "" {
			return deniedCall("sentinel_metadata_response_invalid")
		}
		return nil
	})
	if err != nil {
		return Metadata{}, CallReceipt{}, mapTransportError(ctx, err)
	}
	if !digestPattern.MatchString(decisionDigest) || authenticatedDigest != preflightDigest {
		return Metadata{}, CallReceipt{}, deniedCall("sentinel_transport_receipt_invalid")
	}
	metadata, err := normalizeMetadata(client.config, body)
	if err != nil {
		return Metadata{}, CallReceipt{}, err
	}
	return metadata, CallReceipt{RequestDigest: requestDigest, ResponseDigest: responseDigest,
		LeaseDecisionDigest: decisionDigest, TransportDigest: authenticatedDigest}, nil
}

type vendorMetadata struct {
	Tables        []vendorTable     `json:"tables"`
	Workspaces    []vendorWorkspace `json:"workspaces"`
	Applications  json.RawMessage   `json:"applications,omitempty"`
	Categories    json.RawMessage   `json:"categories,omitempty"`
	Functions     json.RawMessage   `json:"functions,omitempty"`
	Permissions   json.RawMessage   `json:"permissions,omitempty"`
	Queries       json.RawMessage   `json:"queries,omitempty"`
	Resources     json.RawMessage   `json:"resources,omitempty"`
	ResourceTypes json.RawMessage   `json:"resourceTypes,omitempty"`
	Solutions     json.RawMessage   `json:"solutions,omitempty"`
}

type vendorWorkspace struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Region     string          `json:"region"`
	ResourceID string          `json:"resourceId"`
	Related    json.RawMessage `json:"related,omitempty"`
}

type vendorTable struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	TimespanColumn string          `json:"timespanColumn"`
	Columns        []vendorColumn  `json:"columns"`
	Related        json.RawMessage `json:"related,omitempty"`
	Tags           json.RawMessage `json:"tags,omitempty"`
	Properties     json.RawMessage `json:"properties,omitempty"`
}

type vendorColumn struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Description      string `json:"description,omitempty"`
	Source           string `json:"source,omitempty"`
	IsPreferredFacet bool   `json:"isPreferredFacet,omitempty"`
}

func normalizeMetadata(config Config, input []byte) (Metadata, error) {
	var vendor vendorMetadata
	if err := decodeStrictVendor(input, &vendor); err != nil || len(vendor.Workspaces) != 1 ||
		uint32(len(vendor.Tables)) > config.MaximumMetadataTables {
		return Metadata{}, deniedCall("sentinel_metadata_response_invalid")
	}
	workspace := vendor.Workspaces[0]
	if workspace.ID != config.WorkspaceID || workspace.ResourceID != config.WorkspaceResourceID || workspace.Region != config.ExpectedRegion {
		return Metadata{}, conflictCall("sentinel_workspace_identity_mismatch")
	}
	configured := make(map[string]Resource, len(config.Resources))
	for _, resource := range config.Resources {
		configured[resource.Table] = resource
	}
	tables := make([]MetadataTable, 0, len(config.Resources))
	seen := make(map[string]struct{}, len(vendor.Tables))
	var columnCount uint64
	for _, table := range vendor.Tables {
		columnCount += uint64(len(table.Columns))
		if columnCount > uint64(config.MaximumMetadataColumns) {
			return Metadata{}, deniedCall("sentinel_metadata_response_invalid")
		}
		key := strings.ToLower(table.Name)
		if _, exists := seen[key]; exists {
			return Metadata{}, conflictCall("sentinel_metadata_ambiguous")
		}
		seen[key] = struct{}{}
		resource, admitted := configured[table.Name]
		if !admitted {
			continue
		}
		if table.ID == "" || table.TimespanColumn != resource.TimespanColumn || len(table.Columns) == 0 {
			return Metadata{}, conflictCall("sentinel_metadata_drift")
		}
		columns := make([]MetadataColumn, 0, len(table.Columns))
		columnSeen := make(map[string]struct{}, len(table.Columns))
		for _, column := range table.Columns {
			columnKey := strings.ToLower(column.Name)
			if _, exists := columnSeen[columnKey]; exists || !vendorPattern.MatchString(column.Name) ||
				!slices.Contains([]string{"bool", "datetime", "decimal", "dynamic", "guid", "int", "long", "real", "string", "timespan"}, column.Type) {
				return Metadata{}, conflictCall("sentinel_metadata_ambiguous")
			}
			columnSeen[columnKey] = struct{}{}
			columns = append(columns, MetadataColumn{Name: column.Name, Type: column.Type})
		}
		slices.SortFunc(columns, func(left, right MetadataColumn) int { return strings.Compare(left.Name, right.Name) })
		tables = append(tables, MetadataTable{Name: table.Name, TimespanColumn: table.TimespanColumn, Columns: columns})
	}
	if len(tables) != len(config.Resources) {
		return Metadata{}, conflictCall("sentinel_metadata_drift")
	}
	slices.SortFunc(tables, func(left, right MetadataTable) int { return strings.Compare(left.Name, right.Name) })
	metadata := Metadata{SchemaVersion: MetadataVersion, ContractVersion: ContractVersion, WorkspaceID: workspace.ID,
		WorkspaceResourceID: workspace.ResourceID, Region: workspace.Region, APIVersion: APIVersion, Tables: tables}
	metadata.Digest = metadataDigest(metadata)
	if err := validateMetadata(metadata); err != nil {
		return Metadata{}, deniedCall("sentinel_metadata_response_invalid")
	}
	return metadata, nil
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
	if !ok || len(tlsConnection.ConnectionState().PeerCertificates) == 0 {
		return "", deniedCall("sentinel_tls_identity_missing")
	}
	return certificateDigest(tlsConnection.ConnectionState().PeerCertificates[0], client.config.TransportIdentityDigest)
}

func pinnedPeerDigest(response *http.Response, expected string) (string, error) {
	if response == nil || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return "", deniedCall("sentinel_tls_identity_missing")
	}
	return certificateDigest(response.TLS.PeerCertificates[0], expected)
}

func certificateDigest(certificate *x509.Certificate, expected string) (string, error) {
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	value := "sha256:" + hex.EncodeToString(sum[:])
	if value != expected {
		return "", conflictCall("sentinel_tls_identity_mismatch")
	}
	return value, nil
}

func decodeStrictVendor(input []byte, output any) error {
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
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing vendor JSON")
	}
	return nil
}

func validateCallBinding(config Config, binding CallBinding) error {
	if binding.Operation != "sentinel.metadata.get" || binding.TenantID != config.TenantID ||
		binding.Audience != config.TokenAudience || binding.Endpoint != config.Endpoint ||
		binding.TransportIdentityDigest != config.TransportIdentityDigest || !slices.Equal(binding.Targets, binding.Scope.ResourceIDs) {
		return deniedCall("sentinel_call_binding_invalid")
	}
	scope, authority := binding.Scope, binding.Authority
	if !uuidV7Pattern.MatchString(scope.OrganizationID) || !uuidV7Pattern.MatchString(scope.TenantID) ||
		!uuidV7Pattern.MatchString(scope.CaseID) || !uuidV7Pattern.MatchString(authority.ActorID) ||
		scope.SourceID != config.SourceID || !validNames(scope.ResourceIDs, 1, len(config.Resources)) ||
		!validDigests(authority.AuthorizationDigest, authority.PolicyDecisionDigest, authority.AuditReservationDigest) {
		return deniedCall("sentinel_authority_invalid")
	}
	allowed := make(map[string]struct{}, len(config.Resources))
	for _, resource := range config.Resources {
		allowed[resource.ID] = struct{}{}
	}
	for _, resourceID := range scope.ResourceIDs {
		if _, ok := allowed[resourceID]; !ok {
			return deniedCall("sentinel_resource_not_allowed")
		}
	}
	return nil
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

func cloneConfig(value Config) Config {
	encoded, _ := json.Marshal(value)
	var cloned Config
	_ = json.Unmarshal(encoded, &cloned)
	return cloned
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

var uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
