package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type vendorQueryRequest struct {
	Query    string `json:"query"`
	Timespan string `json:"timespan"`
}

type vendorQueryResponse struct {
	Tables     []vendorQueryTable `json:"tables"`
	Statistics json.RawMessage    `json:"statistics,omitempty"`
	Error      *vendorQueryError  `json:"error,omitempty"`
}

type vendorQueryTable struct {
	Name    string              `json:"name"`
	Columns []vendorQueryColumn `json:"columns"`
	Rows    [][]json.RawMessage `json:"rows"`
}

type vendorQueryColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type vendorQueryError struct {
	Code    string                   `json:"code"`
	Message string                   `json:"message"`
	Details []vendorQueryErrorDetail `json:"details"`
}

type vendorQueryErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Query performs the one qualified Logs Query API operation. It deliberately
// shares HTTPClient's pinned TLS and credential boundary with metadata.
func (client *HTTPClient) Query(ctx context.Context, call QueryCall) (QueryTransportResponse, error) {
	if client == nil || client.client == nil || nilPort(client.credentials) {
		return QueryTransportResponse{}, invalidInput("sentinel_http_client_required")
	}
	request, err := admitHTTPQueryCall(client.config, call)
	if err != nil {
		return QueryTransportResponse{}, err
	}
	if err := contextError(ctx); err != nil {
		return QueryTransportResponse{}, err
	}
	preflightDigest, err := client.verifyPeer(ctx)
	if err != nil {
		return QueryTransportResponse{}, mapTransportError(ctx, err)
	}

	path := "/" + APIVersion + "/workspaces/" + client.config.WorkspaceID + "/query"
	requestURL := *client.endpoint
	requestURL.Path, requestURL.RawPath, requestURL.RawQuery = path, "", ""
	payload, _ := json.Marshal(vendorQueryRequest{Query: request.CanonicalKQL,
		Timespan: request.TimeRange.Start + "/" + request.TimeRange.End})
	var body []byte
	var vendorDigest, authenticatedDigest string
	decisionDigest, err := client.credentials.Use(ctx, call.Binding, func(token []byte) error {
		if !validCredential(token) {
			return deniedCall("sentinel_credential_invalid")
		}
		temporary := append([]byte(nil), token...)
		defer func() {
			for index := range temporary {
				temporary[index] = 0
			}
		}()
		httpRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
		if requestErr != nil {
			return invalidInput("sentinel_query_request_invalid")
		}
		httpRequest.Header.Set("Accept", "application/json")
		httpRequest.Header.Set("Content-Type", "application/json")
		httpRequest.Header.Set("Prefer", "include-statistics=true,wait="+strconv.FormatUint(uint64(request.ServerWaitSeconds), 10))
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
		maximum := int64(min(request.MaximumBytes, client.config.HardLimits.MaximumBytes, uint64(maximumContractBytes)))
		body, requestErr = io.ReadAll(io.LimitReader(response.Body, maximum+1))
		if requestErr != nil || int64(len(body)) > maximum {
			return deniedCall("sentinel_response_oversized")
		}
		vendorDigest = hashValue("COH-SENTINEL-VENDOR-QUERY-RESPONSE-V1\x00", struct {
			Status int
			Body   []byte
		}{response.StatusCode, body})
		if response.StatusCode != http.StatusOK {
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
				return deniedCall("sentinel_authentication_or_privilege_denied")
			}
			if response.StatusCode == http.StatusTooManyRequests {
				return queryconnector.NewError(queryconnector.Unavailable, "sentinel_query_throttled", nil)
			}
			return queryconnector.NewError(queryconnector.Unavailable, "sentinel_vendor_unavailable", nil)
		}
		mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/json" || response.Header.Get("Content-Encoding") != "" {
			return deniedCall("sentinel_query_response_invalid")
		}
		return nil
	})
	if err != nil {
		return QueryTransportResponse{}, mapTransportError(ctx, err)
	}
	if !digestPattern.MatchString(decisionDigest) || authenticatedDigest != preflightDigest {
		return QueryTransportResponse{}, deniedCall("sentinel_transport_receipt_invalid")
	}
	return normalizeQueryResponse(request, body, vendorDigest, decisionDigest, authenticatedDigest)
}

func admitHTTPQueryCall(config Config, call QueryCall) (QueryTransportRequest, error) {
	requestBytes := encodeQueryContract(call.Request)
	request, err := DecodeQueryTransportRequest(requestBytes)
	if err != nil {
		return QueryTransportRequest{}, invalidInput("sentinel_query_request_invalid")
	}
	if call.Binding.Operation != QueryOperation {
		return QueryTransportRequest{}, deniedCall("sentinel_operation_denied")
	}
	metadataBinding := call.Binding
	metadataBinding.Operation = "sentinel.metadata.get"
	if err := validateCallBinding(config, metadataBinding); err != nil {
		return QueryTransportRequest{}, err
	}
	if request.SourceID != config.SourceID || request.WorkspaceID != config.WorkspaceID ||
		request.TransportIdentityDigest != config.TransportIdentityDigest ||
		request.ScopeDigest != hashValue("COH-SENTINEL-QUERY-SCOPE-V1\x00", call.Binding.Scope) ||
		request.AuthorityDigest != hashValue("COH-SENTINEL-QUERY-AUTHORITY-V1\x00", call.Binding.Authority) ||
		request.PolicyDecisionDigest != call.Binding.Authority.PolicyDecisionDigest {
		return QueryTransportRequest{}, conflictCall("sentinel_query_binding_mismatch")
	}
	return request, nil
}

func normalizeQueryResponse(request QueryTransportRequest, input []byte, vendorDigest, decisionDigest,
	transportDigest string) (QueryTransportResponse, error) {
	var vendor vendorQueryResponse
	if err := decodeStrictVendor(input, &vendor); err != nil {
		return QueryTransportResponse{}, deniedCall("sentinel_query_response_invalid")
	}
	usageDigest := hashValue("COH-SENTINEL-QUERY-STATISTICS-V1\x00", json.RawMessage(vendor.Statistics))
	receipt := QueryReceipt{Operation: QueryOperation, HTTPStatus: http.StatusOK, RequestDigest: request.RequestDigest,
		VendorResponseDigest: vendorDigest, LeaseDecisionDigest: decisionDigest, TransportDigest: transportDigest,
		TransportIdentityDigest: request.TransportIdentityDigest}
	if vendor.Error != nil {
		if vendor.Error.Code != "PartialError" || len(vendor.Error.Details) == 0 || len(vendor.Error.Details) > 32 {
			return QueryTransportResponse{}, deniedCall("sentinel_query_response_invalid")
		}
		details := make([]string, 0, len(vendor.Error.Details))
		for _, detail := range vendor.Error.Details {
			code := normalizeVendorErrorCode(detail.Code)
			if code == "" {
				return QueryTransportResponse{}, deniedCall("sentinel_query_response_invalid")
			}
			details = append(details, code)
		}
		slices.Sort(details)
		details = slices.Compact(details)
		value := QueryTransportResponse{SchemaVersion: QueryResponseVersion, ContractVersion: ContractVersion,
			RequestDigest: request.RequestDigest, Tables: []QueryTable{}, Statistics: QueryStatistics{
				RowsScanned: 0, RowsReturned: 0, BytesReturned: uint64(len(input)), DurationMillis: 0,
				ResourceUsageDigest: usageDigest}, Error: &QueryAPIError{Code: "PartialError", DetailCodes: details,
				MessageDigest: hashValue("COH-SENTINEL-PARTIAL-ERROR-V1\x00", struct {
					Code, Message string
					Details       []vendorQueryErrorDetail
				}{vendor.Error.Code, vendor.Error.Message, vendor.Error.Details})}, Receipt: receipt}
		value.ResponseDigest = queryTransportResponseDigest(value)
		return DecodeQueryTransportResponse(encodeQueryContract(value))
	}
	if len(vendor.Tables) != 1 || vendor.Tables[0].Name != "PrimaryResult" || len(vendor.Statistics) == 0 {
		return QueryTransportResponse{}, deniedCall("sentinel_query_response_invalid")
	}
	table, err := normalizeQueryTable(vendor.Tables[0])
	if err != nil || uint64(len(table.Rows)) > request.MaximumRows {
		return QueryTransportResponse{}, deniedCall("sentinel_query_response_invalid")
	}
	value := QueryTransportResponse{SchemaVersion: QueryResponseVersion, ContractVersion: ContractVersion,
		RequestDigest: request.RequestDigest, Tables: []QueryTable{table}, Statistics: QueryStatistics{
			RowsScanned: uint64(len(table.Rows)), RowsReturned: uint64(len(table.Rows)), BytesReturned: uint64(len(input)),
			DurationMillis: 0, ResourceUsageDigest: usageDigest}, Error: nil, Receipt: receipt}
	value.ResponseDigest = queryTransportResponseDigest(value)
	return DecodeQueryTransportResponse(encodeQueryContract(value))
}

func normalizeQueryTable(value vendorQueryTable) (QueryTable, error) {
	if len(value.Columns) == 0 || len(value.Columns) > 256 || len(value.Rows) > 100000 {
		return QueryTable{}, deniedCall("sentinel_query_result_invalid")
	}
	columns := make([]QueryColumn, len(value.Columns))
	seen := map[string]struct{}{}
	for index, column := range value.Columns {
		if !vendorPattern.MatchString(column.Name) || !slices.Contains([]string{"bool", "datetime", "decimal", "guid", "int", "long", "real", "string", "timespan"}, column.Type) {
			return QueryTable{}, deniedCall("sentinel_query_result_invalid")
		}
		if _, exists := seen[column.Name]; exists {
			return QueryTable{}, deniedCall("sentinel_query_result_invalid")
		}
		seen[column.Name] = struct{}{}
		columns[index] = QueryColumn{Name: column.Name, Type: column.Type}
	}
	rows := make([][]interface{}, len(value.Rows))
	for rowIndex, source := range value.Rows {
		if len(source) != len(columns) {
			return QueryTable{}, deniedCall("sentinel_query_result_invalid")
		}
		rows[rowIndex] = make([]interface{}, len(source))
		for columnIndex, raw := range source {
			cell, err := normalizeVendorCell(columns[columnIndex].Type, raw)
			if err != nil {
				return QueryTable{}, err
			}
			rows[rowIndex][columnIndex] = cell
		}
	}
	return QueryTable{Name: value.Name, Columns: columns, Rows: rows}, nil
}

func normalizeVendorCell(kind string, raw json.RawMessage) (interface{}, error) {
	if bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	switch kind {
	case "bool":
		var value bool
		if json.Unmarshal(raw, &value) != nil {
			return nil, deniedCall("sentinel_query_result_invalid")
		}
		return value, nil
	case "int", "long":
		value, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil || value > 1<<53 || value < -(1<<53) {
			return nil, deniedCall("sentinel_query_result_invalid")
		}
		return float64(value), nil
	case "real", "decimal":
		value, err := strconv.ParseFloat(string(raw), 64)
		if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
			return nil, deniedCall("sentinel_query_result_invalid")
		}
		return value, nil
	case "datetime", "guid", "string", "timespan":
		var value string
		if json.Unmarshal(raw, &value) != nil || len(value) > 65536 || strings.ContainsRune(value, 0) {
			return nil, deniedCall("sentinel_query_result_invalid")
		}
		if kind == "datetime" {
			if _, ok := queryTime(value); !ok {
				return nil, deniedCall("sentinel_query_result_invalid")
			}
		}
		if kind == "guid" && !uuidPattern.MatchString(value) {
			return nil, deniedCall("sentinel_query_result_invalid")
		}
		return value, nil
	default:
		return nil, deniedCall("sentinel_query_result_invalid")
	}
}

func normalizeVendorErrorCode(value string) string {
	var result strings.Builder
	for index, character := range value {
		if character >= 'A' && character <= 'Z' {
			if index > 0 {
				result.WriteByte('_')
			}
			result.WriteRune(character + ('a' - 'A'))
		} else if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			result.WriteRune(character)
		} else {
			return ""
		}
	}
	output := result.String()
	if !namePattern.MatchString(output) {
		return ""
	}
	return output
}

var _ QueryClient = (*HTTPClient)(nil)
