package skilldiscovery

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumWireBytes = 64 << 10

var (
	searchRequestFields = []string{"actor_id", "case", "contract_version", "cursor", "deadline",
		"expected_snapshot_digest", "idempotency_key", "limit", "policy_digest", "query",
		"request_id", "required_permission", "schema_version", "task_id"}
	detailRequestFields = []string{"actor_id", "case", "contract_version", "deadline",
		"expected_manifest_digest", "expected_search_result_digest", "idempotency_key", "policy_digest",
		"request_id", "required_permission", "schema_version", "search_idempotency_key", "skill_name", "task_id"}
	resourceRequestFields = []string{"actor_id", "case", "contract_version", "deadline",
		"detail_idempotency_key", "expected_detail_result_digest", "expected_manifest_digest", "idempotency_key",
		"policy_digest", "request_id", "required_permission", "resource_digest", "resource_name",
		"schema_version", "skill_name", "task_id"}
)

// CanonicalSearchRequest returns the frozen transport bytes and intent digest.
func CanonicalSearchRequest(value SearchRequest) ([]byte, string, error) {
	if err := validateSearch(value, value.Deadline.Add(-time.Nanosecond)); err != nil {
		return nil, "", err
	}
	wire := searchToWire(value)
	canonical, err := canonicalValue(wire)
	if err != nil {
		return nil, "", err
	}
	intent, err := intentDigest(value)
	return canonical, intent, err
}

// CanonicalDetailRequest returns the frozen transport bytes and intent digest.
func CanonicalDetailRequest(value DetailRequest) ([]byte, string, error) {
	if err := validateDetail(value, value.Deadline.Add(-time.Nanosecond)); err != nil {
		return nil, "", err
	}
	wire := detailToWire(value)
	canonical, err := canonicalValue(wire)
	if err != nil {
		return nil, "", err
	}
	intent, err := intentDigest(value)
	return canonical, intent, err
}

// CanonicalResourceRequest returns the frozen transport bytes and intent digest.
func CanonicalResourceRequest(value ResourceRequest) ([]byte, string, error) {
	if err := validateResource(value, value.Deadline.Add(-time.Nanosecond)); err != nil {
		return nil, "", err
	}
	wire := resourceToWire(value)
	canonical, err := canonicalValue(wire)
	if err != nil {
		return nil, "", err
	}
	intent, err := intentDigest(value)
	return canonical, intent, err
}

func DecodeSearchRequest(input []byte) (SearchRequest, error) {
	var wire searchIntentWire
	if err := decodeExact(input, searchRequestFields, &wire); err != nil {
		return SearchRequest{}, err
	}
	deadline, err := parseWireTime(wire.Deadline)
	if err != nil {
		return SearchRequest{}, err
	}
	value := SearchRequest{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion,
		RequestID: wire.RequestID, IdempotencyKey: wire.IdempotencyKey, Case: caseFromWire(wire.Case),
		TaskID: wire.TaskID, ActorID: wire.ActorID, PolicyDigest: wire.PolicyDigest,
		RequiredPermission: wire.RequiredPermission, Query: wire.Query, Limit: wire.Limit,
		Cursor: wire.Cursor, ExpectedSnapshotDigest: wire.ExpectedSnapshotDigest, Deadline: deadline}
	if err := validateSearch(value, deadline.Add(-time.Nanosecond)); err != nil {
		return SearchRequest{}, err
	}
	return value, nil
}

func DecodeDetailRequest(input []byte) (DetailRequest, error) {
	var wire detailIntentWire
	if err := decodeExact(input, detailRequestFields, &wire); err != nil {
		return DetailRequest{}, err
	}
	deadline, err := parseWireTime(wire.Deadline)
	if err != nil {
		return DetailRequest{}, err
	}
	value := DetailRequest{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion,
		RequestID: wire.RequestID, IdempotencyKey: wire.IdempotencyKey, Case: caseFromWire(wire.Case),
		TaskID: wire.TaskID, ActorID: wire.ActorID, PolicyDigest: wire.PolicyDigest,
		RequiredPermission: wire.RequiredPermission, SkillName: wire.SkillName,
		ExpectedManifestDigest:     wire.ExpectedManifestDigest,
		SearchIdempotencyKey:       wire.SearchIdempotencyKey,
		ExpectedSearchResultDigest: wire.ExpectedSearchResultDigest, Deadline: deadline}
	if err := validateDetail(value, deadline.Add(-time.Nanosecond)); err != nil {
		return DetailRequest{}, err
	}
	return value, nil
}

func DecodeResourceRequest(input []byte) (ResourceRequest, error) {
	var wire resourceIntentWire
	if err := decodeExact(input, resourceRequestFields, &wire); err != nil {
		return ResourceRequest{}, err
	}
	deadline, err := parseWireTime(wire.Deadline)
	if err != nil {
		return ResourceRequest{}, err
	}
	value := ResourceRequest{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion,
		RequestID: wire.RequestID, IdempotencyKey: wire.IdempotencyKey, Case: caseFromWire(wire.Case),
		TaskID: wire.TaskID, ActorID: wire.ActorID, PolicyDigest: wire.PolicyDigest,
		RequiredPermission: wire.RequiredPermission, SkillName: wire.SkillName,
		ExpectedManifestDigest: wire.ExpectedManifestDigest, ResourceName: wire.ResourceName,
		ResourceDigest: wire.ResourceDigest, DetailIdempotencyKey: wire.DetailIdempotencyKey,
		ExpectedDetailResultDigest: wire.ExpectedDetailResultDigest, Deadline: deadline}
	if err := validateResource(value, deadline.Add(-time.Nanosecond)); err != nil {
		return ResourceRequest{}, err
	}
	return value, nil
}

func searchToWire(value SearchRequest) searchIntentWire {
	return searchIntentWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, IdempotencyKey: value.IdempotencyKey, Case: caseToWire(value.Case),
		TaskID: value.TaskID, ActorID: value.ActorID, PolicyDigest: value.PolicyDigest,
		RequiredPermission: value.RequiredPermission, Query: value.Query, Limit: value.Limit,
		Cursor: value.Cursor, ExpectedSnapshotDigest: value.ExpectedSnapshotDigest,
		Deadline: formatTime(value.Deadline)}
}

func detailToWire(value DetailRequest) detailIntentWire {
	return detailIntentWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, IdempotencyKey: value.IdempotencyKey, Case: caseToWire(value.Case),
		TaskID: value.TaskID, ActorID: value.ActorID, PolicyDigest: value.PolicyDigest,
		RequiredPermission: value.RequiredPermission, SkillName: value.SkillName,
		ExpectedManifestDigest:     value.ExpectedManifestDigest,
		SearchIdempotencyKey:       value.SearchIdempotencyKey,
		ExpectedSearchResultDigest: value.ExpectedSearchResultDigest, Deadline: formatTime(value.Deadline)}
}

func resourceToWire(value ResourceRequest) resourceIntentWire {
	return resourceIntentWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, IdempotencyKey: value.IdempotencyKey, Case: caseToWire(value.Case),
		TaskID: value.TaskID, ActorID: value.ActorID, PolicyDigest: value.PolicyDigest,
		RequiredPermission: value.RequiredPermission, SkillName: value.SkillName,
		ExpectedManifestDigest: value.ExpectedManifestDigest, ResourceName: value.ResourceName,
		ResourceDigest: value.ResourceDigest, DetailIdempotencyKey: value.DetailIdempotencyKey,
		ExpectedDetailResultDigest: value.ExpectedDetailResultDigest, Deadline: formatTime(value.Deadline)}
}

func decodeExact(input []byte, expected []string, output any) error {
	if len(input) == 0 || len(input) > maximumWireBytes {
		return newError(InvalidInput, "wire_size_invalid", false, nil)
	}
	decoded, err := domaincontract.DecodeUnique(input)
	object, ok := decoded.(map[string]any)
	if err != nil || !ok {
		return newError(Denied, "wire_duplicate_or_malformed", false, err)
	}
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	slices.Sort(actual)
	if !slices.Equal(actual, expected) {
		return newError(Denied, "wire_fields_invalid", false, nil)
	}
	caseValue, ok := object["case"].(map[string]any)
	if !ok || len(caseValue) != 3 || caseValue["organization_id"] == nil ||
		caseValue["tenant_id"] == nil || caseValue["case_id"] == nil {
		return newError(Denied, "wire_case_invalid", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "wire_malformed", false, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "wire_trailing_data", false, nil)
	}
	canonical, err := canonicalValue(output)
	if err != nil || !bytes.Equal(canonical, input) {
		return newError(Denied, "wire_noncanonical", false, err)
	}
	return nil
}

func parseWireTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(InvalidInput, "wire_timestamp_invalid", false, err)
	}
	return parsed.UTC(), nil
}
