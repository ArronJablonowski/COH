package securityonion

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const maximumAdapterEntries = 4096

type capabilityRecord struct {
	expiresAt time.Time
	resources []string
}

type schemaRecord struct {
	expiresAt  time.Time
	capability string
	resources  []string
	page       queryconnector.ValidatedSchemaPage
}

// Adapter binds qualified Connect identity and configured logical schema to
// the shared read-only query connector discovery contract.
type Adapter struct {
	config        Config
	client        Client
	qualification ValidatedQualification
	clock         Clock

	mu           sync.Mutex
	capabilities map[string]capabilityRecord
	schemas      map[string]schemaRecord
}

func NewAdapter(config Config, client Client, qualification ValidatedQualification, clock Clock) (*Adapter, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if nilPort(client) || nilPort(clock) || qualification.Digest() == "" ||
		qualification.Value().SourceID != config.SourceID || qualification.Value().Digest != qualification.Digest() {
		return nil, invalid("securityonion_adapter_configuration_invalid")
	}
	return &Adapter{config: cloneConfig(config), client: client, qualification: qualification, clock: clock,
		capabilities: make(map[string]capabilityRecord), schemas: make(map[string]schemaRecord)}, nil
}

func (adapter *Adapter) Probe(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (queryconnector.ValidatedCapability, error) {
	if adapter == nil {
		return queryconnector.ValidatedCapability{}, invalid("securityonion_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := adapter.validateScope(scope); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	binding := CallBinding{Scope: scope, Authority: authority, Operation: "securityonion.inspect",
		Targets: append([]string(nil), scope.ResourceIDs...)}
	if err := validateCallBinding(binding, binding.Operation); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	now := adapter.clock.Now().UTC()
	expiresAt, err := adapter.qualificationExpiry(now)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	info, receipt, err := adapter.client.Inspect(ctx, InfoRequest{Binding: binding, Qualification: adapter.qualification})
	if err != nil {
		return queryconnector.ValidatedCapability{}, mapHTTPError(err)
	}
	if err := adapter.validateReceipt(receipt); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if !digestPattern.MatchString(info.ResultDigest) {
		return queryconnector.ValidatedCapability{}, denied("securityonion_identity_result_invalid")
	}
	identityDigest := hashJSON("COH-SECURITY-ONION-SOURCE-IDENTITY-V1\x00", struct {
		Qualification string
		Info          InfoResult
		Receipt       CallReceipt
	}{adapter.qualification.Digest(), info, receipt})
	value := queryconnector.CapabilitySnapshot{SchemaVersion: queryconnector.CapabilitySchemaVersion,
		ContractVersion: queryconnector.ContractVersion,
		SnapshotID:      deterministicUUID(now, identityDigest+scope.OrganizationID+scope.TenantID+scope.CaseID),
		SourceID:        adapter.config.SourceID, AdapterVersion: adapter.config.AdapterVersion,
		ObservedAt: now.Format(timestampLayout), ValidUntil: expiresAt.Format(timestampLayout),
		QueryLanguages: []string{"security-onion-oql"}, Features: queryconnector.Features{ReadOnly: true,
			SchemaDiscovery: true, Validation: true, Polling: true, Cancellation: true, Statistics: true},
		HardLimits: adapter.config.HardLimits, SourceIdentityDigest: identityDigest}
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeCapability(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	if len(adapter.capabilities) >= maximumAdapterEntries {
		adapter.mu.Unlock()
		return queryconnector.ValidatedCapability{}, denied("securityonion_adapter_capacity_reached")
	}
	adapter.capabilities[validated.Digest()] = capabilityRecord{expiresAt: expiresAt,
		resources: append([]string(nil), scope.ResourceIDs...)}
	adapter.mu.Unlock()
	return validated, nil
}

func (adapter *Adapter) DiscoverSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	if adapter == nil {
		return queryconnector.ValidatedSchemaPage{}, invalid("securityonion_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if request.Cursor != nil || !uuidPattern.MatchString(request.RequestID) || !digestPattern.MatchString(request.CapabilityDigest) ||
		!validLimits(request.Limits) || exceedsLimits(request.Limits, adapter.config.HardLimits) {
		return queryconnector.ValidatedSchemaPage{}, invalid("securityonion_schema_request_invalid")
	}
	if err := adapter.validateScope(request.Scope); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	binding := CallBinding{Scope: request.Scope, Authority: request.Authority, Operation: "securityonion.inspect",
		Targets: append([]string(nil), request.Scope.ResourceIDs...)}
	if err := validateCallBinding(binding, binding.Operation); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	now := adapter.clock.Now().UTC()
	if err := adapter.admitCapability(request.Scope, request.CapabilityDigest, now); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	info, receipt, err := adapter.client.Inspect(ctx, InfoRequest{Binding: binding, Qualification: adapter.qualification})
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, mapHTTPError(err)
	}
	if err := adapter.validateReceipt(receipt); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if !digestPattern.MatchString(info.ResultDigest) {
		return queryconnector.ValidatedSchemaPage{}, denied("securityonion_identity_result_invalid")
	}
	entries := make([]queryconnector.SchemaEntry, 0, len(request.Scope.ResourceIDs)*len(adapter.config.Fields))
	for _, resource := range request.Scope.ResourceIDs {
		for _, field := range adapter.config.Fields {
			entries = append(entries, queryconnector.SchemaEntry{ResourceID: resource, Name: field.LogicalName, Type: field.Type})
		}
	}
	slices.SortFunc(entries, func(left, right queryconnector.SchemaEntry) int {
		if compared := strings.Compare(left.ResourceID, right.ResourceID); compared != 0 {
			return compared
		}
		return strings.Compare(left.Name, right.Name)
	})
	schemaDigest := hashJSON("COH-SECURITY-ONION-SCHEMA-V1\x00", entries)
	value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, RequestID: request.RequestID, SchemaDigest: schemaDigest,
		Entries: entries, Complete: true,
		ProvenanceDigest: hashJSON("COH-SECURITY-ONION-SCHEMA-PROVENANCE-V1\x00", struct {
			Capability, Qualification string
			Info                      InfoResult
			Receipt                   CallReceipt
		}{request.CapabilityDigest, adapter.qualification.Digest(), info, receipt})}
	encoded, _ := json.Marshal(value)
	if uint64(len(encoded)) > request.Limits.MaximumBytes {
		return queryconnector.ValidatedSchemaPage{}, denied("securityonion_schema_response_oversized")
	}
	page, err := queryconnector.DecodeSchemaPage(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	if len(adapter.schemas) >= maximumAdapterEntries {
		adapter.mu.Unlock()
		return queryconnector.ValidatedSchemaPage{}, denied("securityonion_adapter_capacity_reached")
	}
	record := adapter.capabilities[request.CapabilityDigest]
	adapter.schemas[request.CapabilityDigest+"\x00"+page.Value().SchemaDigest] = schemaRecord{expiresAt: record.expiresAt,
		capability: request.CapabilityDigest, resources: append([]string(nil), request.Scope.ResourceIDs...), page: page}
	adapter.mu.Unlock()
	return page, nil
}

func (adapter *Adapter) ResolveSchema(ctx context.Context,
	query queryconnector.ValidatedQuery) (queryconnector.ValidatedSchemaPage, error) {
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	value := query.Value()
	now := adapter.clock.Now().UTC()
	if err := adapter.admitCapability(value.Scope, value.CapabilityDigest, now); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	record, ok := adapter.schemas[value.CapabilityDigest+"\x00"+value.SchemaDigest]
	adapter.mu.Unlock()
	if !ok || record.capability != value.CapabilityDigest || !slices.Equal(record.resources, value.Scope.ResourceIDs) {
		return queryconnector.ValidatedSchemaPage{}, conflict("securityonion_schema_binding_mismatch")
	}
	return record.page, nil
}

func (adapter *Adapter) admitCapability(scope queryconnector.Scope, digest string, now time.Time) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.removeExpiredLocked(now)
	record, ok := adapter.capabilities[digest]
	if !ok || !now.Before(record.expiresAt) {
		return denied("securityonion_capability_stale")
	}
	if !slices.Equal(record.resources, scope.ResourceIDs) {
		return conflict("securityonion_capability_scope_mismatch")
	}
	return nil
}

func (adapter *Adapter) validateScope(scope queryconnector.Scope) error {
	if scope.SourceID != adapter.config.SourceID || len(scope.ResourceIDs) == 0 ||
		len(scope.ResourceIDs) > len(adapter.config.Resources) || !slices.IsSorted(scope.ResourceIDs) {
		return denied("securityonion_scope_invalid")
	}
	for index, id := range scope.ResourceIDs {
		if (index > 0 && id == scope.ResourceIDs[index-1]) ||
			!slices.ContainsFunc(adapter.config.Resources, func(resource Resource) bool { return resource.ID == id }) {
			return denied("securityonion_resource_not_allowed")
		}
	}
	return nil
}

func (adapter *Adapter) qualificationExpiry(now time.Time) (time.Time, error) {
	expiresAt, err := time.Parse(timestampLayout, adapter.qualification.Value().ValidUntil)
	if err != nil || !now.Before(expiresAt) {
		return time.Time{}, denied("securityonion_qualification_stale")
	}
	return expiresAt, nil
}

func (adapter *Adapter) validateReceipt(receipt CallReceipt) error {
	if !digestPattern.MatchString(receipt.RequestDigest) || !digestPattern.MatchString(receipt.ResponseDigest) ||
		!digestPattern.MatchString(receipt.LeaseDecisionDigest) || receipt.TransportDigest != adapter.config.TransportIdentityDigest {
		return denied("securityonion_receipt_invalid")
	}
	return nil
}

func (adapter *Adapter) removeExpiredLocked(now time.Time) {
	for key, value := range adapter.capabilities {
		if !now.Before(value.expiresAt) {
			delete(adapter.capabilities, key)
		}
	}
	for key, value := range adapter.schemas {
		if !now.Before(value.expiresAt) {
			delete(adapter.schemas, key)
		}
	}
}

func exceedsLimits(value, maximum queryconnector.Limits) bool {
	return value.MaximumRows > maximum.MaximumRows || value.MaximumBytes > maximum.MaximumBytes ||
		value.MaximumDurationMillis > maximum.MaximumDurationMillis || value.MaximumPages > maximum.MaximumPages ||
		value.MaximumSlices > maximum.MaximumSlices || value.MaximumCostMillionths > maximum.MaximumCostMillionths ||
		value.RequestsPerMinute > maximum.RequestsPerMinute
}

func hashJSON(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	return hash(domain, encoded)
}

func deterministicUUID(now time.Time, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	millis := uint64(now.UnixMilli()) & ((1 << 48) - 1)
	return fmt.Sprintf("%08x-%04x-7%03x-%04x-%012x", uint32(millis>>16), uint16(millis),
		uint16(sum[0])<<4|uint16(sum[1]>>4), uint16(0x8000)|(uint16(sum[2])<<6)|uint16(sum[3]>>2), sum[4:10])
}
