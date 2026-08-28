package sentinel

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

const maximumAdapterRecords = 4096

type sentinelCapabilityRecord struct {
	expiresAt     time.Time
	bindingDigest string
}

type sentinelCursorRecord struct {
	requestDigest, schemaDigest, provenanceDigest string
	entries                                       []queryconnector.SchemaEntry
	offset                                        int
	issuedAt, expiresAt                           time.Time
}

type sentinelSchemaReplay struct {
	page      queryconnector.ValidatedSchemaPage
	expiresAt time.Time
}

type sentinelSchemaFlight struct {
	done      chan struct{}
	page      queryconnector.ValidatedSchemaPage
	err       error
	expiresAt time.Time
}

type Adapter struct {
	config        Config
	client        Client
	qualification ValidatedQualification
	clock         Clock

	mu           sync.Mutex
	capabilities map[string]sentinelCapabilityRecord
	cursors      map[string]sentinelCursorRecord
	replays      map[string]sentinelSchemaReplay
	flights      map[string]*sentinelSchemaFlight
}

func NewAdapter(config Config, client Client, qualification ValidatedQualification, clock Clock) (*Adapter, error) {
	if err := validateConfig(config); err != nil || nilPort(client) || nilPort(clock) || qualification.Digest() == "" {
		return nil, invalidInput("sentinel_adapter_configuration_invalid")
	}
	qualified := qualification.Value()
	if qualified.Digest != qualification.Digest() || qualified.SourceID != config.SourceID ||
		qualified.AdapterVersion != config.AdapterVersion || qualified.ConfigDigest != hashValue("COH-SENTINEL-CONFIG-V1\x00", config) ||
		qualified.WorkspaceID != config.WorkspaceID || qualified.WorkspaceResourceID != config.WorkspaceResourceID ||
		qualified.Region != config.ExpectedRegion || qualified.APIVersion != config.APIVersion {
		return nil, conflictCall("sentinel_qualification_configuration_mismatch")
	}
	return &Adapter{config: cloneConfig(config), client: client, qualification: qualification, clock: clock,
		capabilities: make(map[string]sentinelCapabilityRecord), cursors: make(map[string]sentinelCursorRecord),
		replays: make(map[string]sentinelSchemaReplay), flights: make(map[string]*sentinelSchemaFlight)}, nil
}

func (adapter *Adapter) Probe(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (queryconnector.ValidatedCapability, error) {
	if adapter == nil {
		return queryconnector.ValidatedCapability{}, invalidInput("sentinel_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateAdapterScope(adapter.config, scope); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	binding := adapter.callBinding(scope, authority)
	if err := validateCallBinding(adapter.config, binding); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	now := adapter.clock.Now().UTC()
	expiresAt, err := adapter.qualificationExpiry(now)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	metadata, receipt, err := adapter.client.Metadata(ctx, MetadataRequest{Binding: binding})
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := adapter.admitLiveMetadata(metadata, receipt); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	identityDigest := hashValue("COH-SENTINEL-SOURCE-IDENTITY-V1\x00", struct {
		Qualification string
		Scope         queryconnector.Scope
		Authority     queryconnector.AuthorityBinding
		Metadata      string
		Receipt       CallReceipt
	}{adapter.qualification.Digest(), scope, authority, metadata.Digest, receipt})
	value := queryconnector.CapabilitySnapshot{SchemaVersion: queryconnector.CapabilitySchemaVersion,
		ContractVersion: queryconnector.ContractVersion, SnapshotID: sentinelDeterministicUUID(now, identityDigest),
		SourceID: adapter.config.SourceID, AdapterVersion: adapter.config.AdapterVersion,
		ObservedAt: now.Format(sentinelTimestampLayout), ValidUntil: expiresAt.Format(sentinelTimestampLayout),
		QueryLanguages: []string{"kql"}, Features: queryconnector.Features{ReadOnly: true, SchemaDiscovery: true,
			Validation: true, Polling: false, Paging: false, Cancellation: false, Statistics: false},
		HardLimits: adapter.config.HardLimits, SourceIdentityDigest: identityDigest}
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeCapability(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.removeExpiredLocked(now)
	if _, exists := adapter.capabilities[validated.Digest()]; !exists && len(adapter.capabilities) >= maximumAdapterRecords {
		return queryconnector.ValidatedCapability{}, deniedCall("sentinel_adapter_capacity_reached")
	}
	adapter.capabilities[validated.Digest()] = sentinelCapabilityRecord{expiresAt: expiresAt,
		bindingDigest: adapter.bindingDigest(scope, authority)}
	return validated, nil
}

func (adapter *Adapter) DiscoverSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	if adapter == nil {
		return queryconnector.ValidatedSchemaPage{}, invalidInput("sentinel_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if err := validateSchemaRequest(adapter.config, request); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	now := adapter.clock.Now().UTC()
	record, err := adapter.admitCapability(request, now)
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if request.Cursor != nil {
		return adapter.loadCursor(ctx, request, now)
	}
	key := sentinelSchemaRequestDigest(request)
	flight, leader, replay, err := adapter.schemaFlight(key, now, record.expiresAt)
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if replay.Digest() != "" {
		return replay, nil
	}
	if !leader {
		return adapter.waitSchemaFlight(ctx, flight)
	}
	page, loadErr := adapter.loadSchema(ctx, request, now, record)
	adapter.finishSchemaFlight(key, flight, page, loadErr)
	return page, loadErr
}

func (adapter *Adapter) loadSchema(ctx context.Context, request queryconnector.SchemaRequest, now time.Time,
	record sentinelCapabilityRecord) (queryconnector.ValidatedSchemaPage, error) {
	binding := adapter.callBinding(request.Scope, request.Authority)
	metadata, receipt, err := adapter.client.Metadata(ctx, MetadataRequest{Binding: binding})
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if err := adapter.admitLiveMetadata(metadata, receipt); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	entries, err := adapter.schemaEntries(request.Scope.ResourceIDs)
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if len(entries) == 0 || uint64(len(entries)) > uint64(adapter.config.MaximumSchemaEntriesPerPage)*uint64(request.Limits.MaximumPages) {
		return queryconnector.ValidatedSchemaPage{}, deniedCall("sentinel_schema_page_limit_exceeded")
	}
	schemaDigest := hashValue("COH-SENTINEL-SCHEMA-V1\x00", struct {
		Qualification, Capability, Metadata string
		Entries                             []queryconnector.SchemaEntry
	}{adapter.qualification.Digest(), request.CapabilityDigest, metadata.Digest, entries})
	provenanceDigest := hashValue("COH-SENTINEL-DISCOVERY-PROVENANCE-V1\x00", struct {
		Request, Qualification, Metadata string
		Receipt                          CallReceipt
	}{sentinelSchemaRequestDigest(request), adapter.qualification.Digest(), metadata.Digest, receipt})
	cursor := sentinelCursorRecord{requestDigest: sentinelSchemaRequestDigest(request), schemaDigest: schemaDigest,
		provenanceDigest: provenanceDigest, entries: entries, issuedAt: now, expiresAt: record.expiresAt}
	return adapter.page(ctx, request, cursor)
}

func (adapter *Adapter) schemaEntries(resourceIDs []string) ([]queryconnector.SchemaEntry, error) {
	selected := make(map[string]struct{}, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		selected[resourceID] = struct{}{}
	}
	entries := make([]queryconnector.SchemaEntry, 0, len(adapter.config.Fields)*len(resourceIDs))
	for _, field := range adapter.config.Fields {
		if field.Type == "number" {
			return nil, queryconnector.NewError(queryconnector.Unsupported, "sentinel_schema_type_unrepresentable", nil)
		}
		for _, resourceID := range field.ResourceIDs {
			if _, ok := selected[resourceID]; ok {
				entries = append(entries, queryconnector.SchemaEntry{ResourceID: resourceID, Name: field.SchemaName,
					Type: field.Type, Nullable: field.Nullable})
			}
		}
	}
	slices.SortFunc(entries, func(left, right queryconnector.SchemaEntry) int {
		if compared := strings.Compare(left.ResourceID, right.ResourceID); compared != 0 {
			return compared
		}
		return strings.Compare(left.Name, right.Name)
	})
	return entries, nil
}

func (adapter *Adapter) Validate(ctx context.Context,
	query queryconnector.ValidatedQuery) (queryconnector.ValidatedValidation, error) {
	if adapter == nil || query.Digest() == "" {
		return queryconnector.ValidatedValidation{}, invalidInput("sentinel_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	value := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.Value().QueryID, Outcome: "denied",
		ReasonCodes: []string{"sentinel_validator_unavailable"}, ValidatorVersion: "sentinel-kql-disabled-1.0.0",
		CanonicalQueryDigest: query.Digest(), ProvenanceDigest: hashValue("COH-SENTINEL-VALIDATION-DENIAL-V1\x00", struct {
			Qualification, Query string
		}{adapter.qualification.Digest(), query.Digest()})}
	encoded, _ := json.Marshal(value)
	return queryconnector.DecodeValidation(ctx, encoded)
}

func (adapter *Adapter) Execute(ctx context.Context, _ queryconnector.ValidatedQuery,
	_ queryconnector.ValidatedValidation) (queryconnector.ValidatedExecution, error) {
	return queryconnector.ValidatedExecution{}, adapter.unsupported(ctx, "sentinel_execution_unsupported")
}

func (adapter *Adapter) Poll(ctx context.Context, _ queryconnector.PollRequest) (queryconnector.ValidatedPoll, error) {
	return queryconnector.ValidatedPoll{}, adapter.unsupported(ctx, "sentinel_polling_unsupported")
}

func (adapter *Adapter) NextPage(ctx context.Context, _ queryconnector.PageRequest) (queryconnector.ValidatedPage, error) {
	return queryconnector.ValidatedPage{}, adapter.unsupported(ctx, "sentinel_paging_unsupported")
}

func (adapter *Adapter) Cancel(ctx context.Context, _ queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error) {
	return queryconnector.ValidatedCancellation{}, adapter.unsupported(ctx, "sentinel_cancellation_unsupported")
}

func (adapter *Adapter) unsupported(ctx context.Context, reason string) error {
	if adapter == nil {
		return invalidInput("sentinel_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	return queryconnector.NewError(queryconnector.Unsupported, reason, nil)
}

func (adapter *Adapter) LoadSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	return adapter.DiscoverSchema(ctx, request)
}

func (adapter *Adapter) callBinding(scope queryconnector.Scope, authority queryconnector.AuthorityBinding) CallBinding {
	return CallBinding{Scope: scope, Authority: authority, Operation: "sentinel.metadata.get",
		Targets: append([]string(nil), scope.ResourceIDs...), TenantID: adapter.config.TenantID,
		Audience: adapter.config.TokenAudience, Endpoint: adapter.config.Endpoint,
		TransportIdentityDigest: adapter.config.TransportIdentityDigest}
}

func (adapter *Adapter) admitLiveMetadata(metadata Metadata, receipt CallReceipt) error {
	if err := validateQualificationReceipt(adapter.config, receipt); err != nil {
		return err
	}
	if err := validateLiveMetadata(adapter.config, metadata); err != nil {
		return err
	}
	if metadata.Digest != adapter.qualification.Value().MetadataDigest {
		return conflictCall("sentinel_qualification_drift")
	}
	return nil
}

func (adapter *Adapter) qualificationExpiry(now time.Time) (time.Time, error) {
	expiresAt, err := time.Parse(sentinelTimestampLayout, adapter.qualification.Value().ValidUntil)
	if err != nil || !now.Before(expiresAt) {
		return time.Time{}, deniedCall("sentinel_qualification_stale")
	}
	return expiresAt, nil
}

func (adapter *Adapter) bindingDigest(scope queryconnector.Scope, authority queryconnector.AuthorityBinding) string {
	return hashValue("COH-SENTINEL-CAPABILITY-BINDING-V1\x00", struct {
		Scope     queryconnector.Scope
		Authority queryconnector.AuthorityBinding
	}{scope, authority})
}

func sentinelDeterministicUUID(now time.Time, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	millis := uint64(now.UnixMilli()) & ((1 << 48) - 1)
	return fmt.Sprintf("%08x-%04x-7%03x-%04x-%012x", uint32(millis>>16), uint16(millis),
		uint16(sum[0])<<4|uint16(sum[1]>>4), uint16(0x8000)|(uint16(sum[2])<<6)|uint16(sum[3]>>2), sum[4:10])
}

var _ queryconnector.Connector = (*Adapter)(nil)
