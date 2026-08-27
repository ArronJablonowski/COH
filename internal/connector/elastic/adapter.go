package elastic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

type capabilityRecord struct {
	expiresAt time.Time
	resources []string
}

type cursorRecord struct {
	requestDigest    string
	schemaDigest     string
	provenanceDigest string
	entries          []queryconnector.SchemaEntry
	offset           int
	issuedAt         time.Time
	expiresAt        time.Time
}

// Adapter owns capability admission and normalized schema production. Network
// authentication remains behind the typed Client boundary.
type Adapter struct {
	config Config
	client Client
	clock  Clock

	mu           sync.Mutex
	capabilities map[string]capabilityRecord
	cursors      map[string]cursorRecord
}

func New(config Config, client Client, clock Clock) (*Adapter, error) {
	if err := validateConfig(config); err != nil || nilPort(client) || nilPort(clock) {
		if err != nil {
			return nil, err
		}
		return nil, invalid("elastic_port_required")
	}
	return &Adapter{config: cloneConfig(config), client: client, clock: clock, capabilities: make(map[string]capabilityRecord),
		cursors: make(map[string]cursorRecord)}, nil
}

func cloneConfig(config Config) Config {
	config.QualifiedMinorVersions = append([]string(nil), config.QualifiedMinorVersions...)
	config.Resources = append([]Resource(nil), config.Resources...)
	config.Fields = append([]Field(nil), config.Fields...)
	return config
}

func (adapter *Adapter) Probe(ctx context.Context, scope queryconnector.Scope, authority queryconnector.AuthorityBinding) (queryconnector.ValidatedCapability, error) {
	if adapter == nil {
		return queryconnector.ValidatedCapability{}, invalid("elastic_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	resources, err := validateScope(adapter.config, scope)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateBinding(scope, authority); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	binding := CallBinding{Scope: scope, Authority: authority, Operation: "elastic.inspect", Targets: resourceIDs(resources)}
	identity, receipt, err := adapter.client.Inspect(ctx, binding)
	if err != nil {
		return queryconnector.ValidatedCapability{}, mapClientError(err)
	}
	if err := validateIdentity(adapter.config, identity); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateReceipt(adapter.config, receipt); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	now := adapter.clock.Now().UTC()
	expiresAt := now.Add(adapter.config.CapabilityLifetime)
	identityDigest := digest("COH-ELASTIC-SOURCE-IDENTITY-V1\x00", struct {
		Config   Config
		Identity ClusterIdentity
		Receipt  CallReceipt
	}{adapter.config, identity, receipt})
	value := queryconnector.CapabilitySnapshot{
		SchemaVersion: queryconnector.CapabilitySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		SnapshotID: deterministicUUID(now, identityDigest+scope.OrganizationID+scope.TenantID+scope.CaseID),
		SourceID:   adapter.config.SourceID, AdapterVersion: adapter.config.AdapterVersion,
		ObservedAt: now.Format(timestampLayout), ValidUntil: expiresAt.Format(timestampLayout),
		QueryLanguages: []string{"elastic-query-dsl", "esql"},
		Features: queryconnector.Features{ReadOnly: true, SchemaDiscovery: true, Validation: true,
			Polling: true, Paging: true, Cancellation: true, Statistics: true},
		HardLimits: adapter.config.HardLimits, SourceIdentityDigest: identityDigest,
	}
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeCapability(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	adapter.capabilities[validated.Digest()] = capabilityRecord{expiresAt: expiresAt, resources: append([]string(nil), scope.ResourceIDs...)}
	adapter.mu.Unlock()
	return validated, nil
}

func (adapter *Adapter) DiscoverSchema(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	return adapter.LoadSchema(ctx, request)
}

func (adapter *Adapter) LoadSchema(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	if adapter == nil {
		return queryconnector.ValidatedSchemaPage{}, invalid("elastic_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	resources, err := validateScope(adapter.config, request.Scope)
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if !uuidPattern.MatchString(request.RequestID) || !digestPattern.MatchString(request.CapabilityDigest) ||
		!validLimits(request.Limits) || exceeds(request.Limits, adapter.config.HardLimits) {
		return queryconnector.ValidatedSchemaPage{}, invalid("elastic_schema_request_invalid")
	}
	if err := validateBinding(request.Scope, request.Authority); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	now := adapter.clock.Now().UTC()
	if err := adapter.admitCapability(request, now); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if request.Cursor != nil {
		return adapter.loadCursor(ctx, request, now)
	}
	if uint64(len(resources)*len(adapter.config.Fields)) > uint64(adapter.config.MaximumSchemaEntriesPerPage)*uint64(request.Limits.MaximumPages) {
		return queryconnector.ValidatedSchemaPage{}, denied("elastic_schema_page_limit_exceeded")
	}
	identity, inspectReceipt, err := adapter.client.Inspect(ctx, CallBinding{Scope: request.Scope,
		Authority: request.Authority, Operation: "elastic.inspect", Targets: resourceIDs(resources)})
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, mapClientError(err)
	}
	if err := validateIdentity(adapter.config, identity); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if err := validateReceipt(adapter.config, inspectReceipt); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}

	entries := make([]queryconnector.SchemaEntry, 0, len(resources)*len(adapter.config.Fields))
	provenance := []any{identity, inspectReceipt}
	for _, resource := range resources {
		resolved, resolveReceipt, err := adapter.client.Resolve(ctx, ResolveRequest{Binding: CallBinding{Scope: request.Scope,
			Authority: request.Authority, Operation: "elastic.resolve", Targets: []string{resource.ID}},
			Expression: resource.Expression, Expand: "open"})
		if err != nil {
			return queryconnector.ValidatedSchemaPage{}, mapClientError(err)
		}
		if err := validateReceipt(adapter.config, resolveReceipt); err != nil {
			return queryconnector.ValidatedSchemaPage{}, err
		}
		indices, err := normalizeResolution(resource, resolved)
		if err != nil {
			return queryconnector.ValidatedSchemaPage{}, err
		}
		caps, capsReceipt, err := adapter.client.FieldCapabilities(ctx, FieldCapabilitiesRequest{
			Binding: CallBinding{Scope: request.Scope, Authority: request.Authority, Operation: "elastic.field_caps", Targets: indices},
			Indices: indices, Fields: vendorFields(adapter.config.Fields), AllowNoIndices: false,
			IgnoreUnavailable: false, ExpandWildcards: "open", IncludeUnmapped: true,
		})
		if err != nil {
			return queryconnector.ValidatedSchemaPage{}, mapClientError(err)
		}
		if err := validateReceipt(adapter.config, capsReceipt); err != nil {
			return queryconnector.ValidatedSchemaPage{}, err
		}
		resourceEntries, err := normalizeCapabilities(resource, adapter.config.Fields, indices, caps)
		if err != nil {
			return queryconnector.ValidatedSchemaPage{}, err
		}
		entries = append(entries, resourceEntries...)
		provenance = append(provenance, resource, resolved, resolveReceipt, caps, capsReceipt)
	}
	if len(entries) == 0 {
		return queryconnector.ValidatedSchemaPage{}, denied("elastic_schema_size_invalid")
	}
	slices.SortFunc(entries, func(left, right queryconnector.SchemaEntry) int {
		if compared := strings.Compare(left.ResourceID, right.ResourceID); compared != 0 {
			return compared
		}
		return strings.Compare(left.Name, right.Name)
	})
	schemaDigest := digest("COH-ELASTIC-SCHEMA-V1\x00", entries)
	provenanceDigest := digest("COH-ELASTIC-DISCOVERY-PROVENANCE-V1\x00", struct {
		RequestDigest string
		Records       []any
	}{request.CapabilityDigest, provenance})
	adapter.mu.Lock()
	record := adapter.capabilities[request.CapabilityDigest]
	adapter.mu.Unlock()
	cursor := cursorRecord{requestDigest: cursorRequestDigest(request), schemaDigest: schemaDigest,
		provenanceDigest: provenanceDigest, entries: entries, issuedAt: now, expiresAt: record.expiresAt}
	return adapter.page(ctx, request, cursor)
}

func (adapter *Adapter) admitCapability(request queryconnector.SchemaRequest, now time.Time) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.removeExpiredLocked(now)
	record, ok := adapter.capabilities[request.CapabilityDigest]
	if !ok || !now.Before(record.expiresAt) {
		return denied("elastic_capability_stale")
	}
	if !slices.Equal(record.resources, request.Scope.ResourceIDs) {
		return conflict("elastic_capability_scope_mismatch")
	}
	return nil
}

func (adapter *Adapter) removeExpiredLocked(now time.Time) {
	for key, record := range adapter.capabilities {
		if !now.Before(record.expiresAt) {
			delete(adapter.capabilities, key)
		}
	}
	for key, record := range adapter.cursors {
		if !now.Before(record.expiresAt) {
			delete(adapter.cursors, key)
		}
	}
}

func (adapter *Adapter) loadCursor(ctx context.Context, request queryconnector.SchemaRequest, now time.Time) (queryconnector.ValidatedSchemaPage, error) {
	provided := *request.Cursor
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	record, ok := adapter.cursors[provided.HandleID]
	adapter.mu.Unlock()
	if !ok || !now.Before(record.expiresAt) {
		return queryconnector.ValidatedSchemaPage{}, denied("elastic_schema_cursor_stale")
	}
	expected := adapter.cursorHandle(record)
	if provided != expected || record.requestDigest != cursorRequestDigest(request) {
		return queryconnector.ValidatedSchemaPage{}, conflict("elastic_schema_cursor_mismatch")
	}
	return adapter.page(ctx, request, record)
}

func (adapter *Adapter) page(ctx context.Context, request queryconnector.SchemaRequest, record cursorRecord) (queryconnector.ValidatedSchemaPage, error) {
	if record.offset < 0 || record.offset >= len(record.entries) {
		return queryconnector.ValidatedSchemaPage{}, denied("elastic_schema_cursor_invalid")
	}
	end := min(record.offset+adapter.config.MaximumSchemaEntriesPerPage, len(record.entries))
	for end > record.offset {
		complete := end == len(record.entries)
		var next *queryconnector.HandleRef
		if !complete {
			nextRecord := record
			nextRecord.offset = end
			handle := adapter.cursorHandle(nextRecord)
			next = &handle
		}
		value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion,
			ContractVersion: queryconnector.ContractVersion, RequestID: request.RequestID,
			SchemaDigest: record.schemaDigest, Entries: append([]queryconnector.SchemaEntry(nil), record.entries[record.offset:end]...),
			NextCursor: next, Complete: complete,
			ProvenanceDigest: digest("COH-ELASTIC-SCHEMA-PAGE-V1\x00", struct {
				Discovery string
				Offset    int
				End       int
			}{record.provenanceDigest, record.offset, end}),
		}
		encoded, _ := json.Marshal(value)
		if uint64(len(encoded)) <= request.Limits.MaximumBytes {
			validated, err := queryconnector.DecodeSchemaPage(ctx, encoded)
			if err != nil {
				return queryconnector.ValidatedSchemaPage{}, err
			}
			if next != nil {
				nextRecord := record
				nextRecord.offset = end
				adapter.mu.Lock()
				adapter.cursors[next.HandleID] = nextRecord
				adapter.mu.Unlock()
			}
			return validated, nil
		}
		end--
	}
	return queryconnector.ValidatedSchemaPage{}, denied("elastic_schema_page_oversized")
}

func (adapter *Adapter) cursorHandle(record cursorRecord) queryconnector.HandleRef {
	opaque := digest("COH-ELASTIC-SCHEMA-CURSOR-V1\x00", struct {
		Request    string
		Schema     string
		Provenance string
		Offset     int
		ExpiresAt  string
	}{record.requestDigest, record.schemaDigest, record.provenanceDigest, record.offset, record.expiresAt.Format(timestampLayout)})
	return queryconnector.HandleRef{HandleID: deterministicUUID(record.issuedAt, opaque), Kind: "schema_cursor",
		SourceID: adapter.config.SourceID, OpaqueDigest: opaque, IssuedAt: record.issuedAt.Format(timestampLayout),
		ExpiresAt: record.expiresAt.Format(timestampLayout)}
}

func cursorRequestDigest(request queryconnector.SchemaRequest) string {
	request.Cursor = nil
	return digest("COH-ELASTIC-SCHEMA-REQUEST-V1\x00", request)
}

func resourceIDs(resources []Resource) []string {
	values := make([]string, len(resources))
	for index, resource := range resources {
		values[index] = resource.ID
	}
	return values
}

func vendorFields(fields []Field) []string {
	values := make([]string, len(fields))
	for index, field := range fields {
		values[index] = field.VendorName
	}
	return values
}

func exceeds(value, maximum queryconnector.Limits) bool {
	return value.MaximumRows > maximum.MaximumRows || value.MaximumBytes > maximum.MaximumBytes ||
		value.MaximumDurationMillis > maximum.MaximumDurationMillis || value.MaximumPages > maximum.MaximumPages ||
		value.MaximumSlices > maximum.MaximumSlices || value.MaximumCostMillionths > maximum.MaximumCostMillionths ||
		value.RequestsPerMinute > maximum.RequestsPerMinute
}

func digest(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(domain), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func deterministicUUID(now time.Time, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	millis := uint64(now.UnixMilli()) & ((1 << 48) - 1)
	return fmt.Sprintf("%08x-%04x-7%03x-%04x-%012x", uint32(millis>>16), uint16(millis),
		uint16(sum[0])<<4|uint16(sum[1]>>4), uint16(0x8000)|(uint16(sum[2])<<6)|uint16(sum[3]>>2), sum[4:10])
}

func mapClientError(err error) error {
	var connectorError *queryconnector.Error
	if errors.As(err, &connectorError) {
		return err
	}
	return queryconnector.NewError(queryconnector.Unavailable, "elastic_transport_unavailable", nil)
}
