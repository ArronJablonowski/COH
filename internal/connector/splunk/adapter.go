package splunk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const maximumAdapterRecords = 4096

type splunkCapabilityRecord struct {
	expiresAt time.Time
	resources []string
}

type splunkCursorRecord struct {
	requestDigest, schemaDigest, provenanceDigest string
	entries                                       []queryconnector.SchemaEntry
	offset                                        int
	issuedAt, expiresAt                           time.Time
}

type splunkSchemaRecord struct {
	capabilityDigest string
	expiresAt        time.Time
	entries          []queryconnector.SchemaEntry
}

type splunkValidationRecord struct {
	queryID    string
	validation queryconnector.ValidatedValidation
	plan       splunkparser.Plan
	expiresAt  time.Time
}

type Adapter struct {
	config        Config
	client        Client
	qualification ValidatedQualification
	clock         Clock

	mu           sync.Mutex
	capabilities map[string]splunkCapabilityRecord
	cursors      map[string]splunkCursorRecord
	schemas      map[string]splunkSchemaRecord
	validations  map[string]splunkValidationRecord
	queryIDs     map[string]string
	revoked      map[string]string
}

func NewAdapter(config Config, client Client, qualification ValidatedQualification, clock Clock) (*Adapter, error) {
	if err := validateConfig(config); err != nil || nilPort(client) || nilPort(clock) || qualification.Digest() == "" {
		return nil, invalidInput("splunk_adapter_configuration_invalid")
	}
	qualified := qualification.Value()
	if qualified.Digest != qualification.Digest() || qualified.SourceID != config.SourceID ||
		qualified.AdapterVersion != config.AdapterVersion || qualified.ConfigDigest != hashValue("COH-SPLUNK-CONFIG-V1\x00", config) {
		return nil, conflictCall("splunk_qualification_configuration_mismatch")
	}
	return &Adapter{config: cloneConfig(config), client: client, qualification: qualification, clock: clock,
		capabilities: make(map[string]splunkCapabilityRecord), cursors: make(map[string]splunkCursorRecord),
		schemas: make(map[string]splunkSchemaRecord), validations: make(map[string]splunkValidationRecord),
		queryIDs: make(map[string]string), revoked: make(map[string]string)}, nil
}

func (adapter *Adapter) Probe(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (queryconnector.ValidatedCapability, error) {
	if adapter == nil {
		return queryconnector.ValidatedCapability{}, invalidInput("splunk_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateAdapterScope(adapter.config, scope); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateAuthority(adapter.config, CallBinding{Scope: scope, Authority: authority}); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	now := adapter.clock.Now().UTC()
	expiresAt, err := adapter.qualificationExpiry(now)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	identityBinding := CallBinding{Scope: scope, Authority: authority, Operation: "splunk.server_info", Targets: append([]string(nil), scope.ResourceIDs...)}
	identity, identityReceipt, err := adapter.client.ServerInfo(ctx, identityBinding)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateQualificationReceipt(adapter.config, identityReceipt); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateServerIdentity(adapter.config, identity); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	capabilityBinding := CallBinding{Scope: scope, Authority: authority, Operation: "splunk.current_context", Targets: append([]string(nil), scope.ResourceIDs...)}
	current, capabilityReceipt, err := adapter.client.CurrentContext(ctx, capabilityBinding)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateQualificationReceipt(adapter.config, capabilityReceipt); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	if err := validateCurrentCapabilities(adapter.config, current.Capabilities); err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	qualified := adapter.qualification.Value()
	if identity.GUID != qualified.ServerGUID || identity.Version != qualified.Version || identity.Build != qualified.Build ||
		!slices.Equal(identity.ServerRoles, qualified.ServerRoles) || !slices.Equal(current.Capabilities, qualified.Capabilities) {
		return queryconnector.ValidatedCapability{}, conflictCall("splunk_qualification_drift")
	}
	identityDigest := hashValue("COH-SPLUNK-SOURCE-IDENTITY-V1\x00", struct {
		Qualification string
		Scope         queryconnector.Scope
		Identity      ServerIdentity
		Capabilities  []string
		Receipts      []CallReceipt
	}{adapter.qualification.Digest(), scope, identity, current.Capabilities, []CallReceipt{identityReceipt, capabilityReceipt}})
	value := queryconnector.CapabilitySnapshot{SchemaVersion: queryconnector.CapabilitySchemaVersion,
		ContractVersion: queryconnector.ContractVersion, SnapshotID: splunkDeterministicUUID(now, identityDigest),
		SourceID: adapter.config.SourceID, AdapterVersion: adapter.config.AdapterVersion,
		ObservedAt: now.Format(splunkTimestampLayout), ValidUntil: expiresAt.Format(splunkTimestampLayout),
		QueryLanguages: []string{"spl"}, Features: queryconnector.Features{ReadOnly: true, SchemaDiscovery: true, Validation: true},
		HardLimits: adapter.config.HardLimits, SourceIdentityDigest: identityDigest}
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeCapability(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.removeExpiredLocked(now)
	if len(adapter.capabilities) >= maximumAdapterRecords {
		return queryconnector.ValidatedCapability{}, deniedCall("splunk_adapter_capacity_reached")
	}
	adapter.capabilities[validated.Digest()] = splunkCapabilityRecord{expiresAt: expiresAt,
		resources: append([]string(nil), scope.ResourceIDs...)}
	return validated, nil
}

func (adapter *Adapter) DiscoverSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	if adapter == nil {
		return queryconnector.ValidatedSchemaPage{}, invalidInput("splunk_adapter_required")
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
	binding := CallBinding{Scope: request.Scope, Authority: request.Authority, Operation: "splunk.indexes",
		Targets: append([]string(nil), request.Scope.ResourceIDs...)}
	indexes, indexReceipt, err := adapter.client.Indexes(ctx, InventoryRequest{Binding: binding,
		MaximumEntries: adapter.config.MaximumInventoryEntries})
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if err := validateQualificationReceipt(adapter.config, indexReceipt); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if indexes.Truncated {
		return queryconnector.ValidatedSchemaPage{}, queryconnector.NewError(queryconnector.Unsupported, "splunk_index_inventory_truncated", nil)
	}
	resources, err := normalizeIndexes(adapter.config, request.Scope.ResourceIDs, indexes)
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	binding.Operation = "splunk.fields"
	fields, fieldReceipt, err := adapter.client.RegisteredFields(ctx, InventoryRequest{Binding: binding,
		MaximumEntries: adapter.config.MaximumInventoryEntries})
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if err := validateQualificationReceipt(adapter.config, fieldReceipt); err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if fields.Truncated {
		return queryconnector.ValidatedSchemaPage{}, queryconnector.NewError(queryconnector.Unsupported, "splunk_field_inventory_truncated", nil)
	}
	entries, err := normalizeFields(adapter.config, resources, fields)
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	if len(entries) == 0 || uint64(len(entries)) > uint64(adapter.config.MaximumSchemaEntriesPerPage)*uint64(request.Limits.MaximumPages) {
		return queryconnector.ValidatedSchemaPage{}, deniedCall("splunk_schema_page_limit_exceeded")
	}
	schemaDigest := hashValue("COH-SPLUNK-SCHEMA-V1\x00", entries)
	adapter.mu.Lock()
	if len(adapter.schemas) >= maximumAdapterRecords {
		adapter.mu.Unlock()
		return queryconnector.ValidatedSchemaPage{}, deniedCall("splunk_adapter_capacity_reached")
	}
	adapter.schemas[schemaRecordKey(request.CapabilityDigest, schemaDigest)] = splunkSchemaRecord{
		capabilityDigest: request.CapabilityDigest, expiresAt: record.expiresAt, entries: append([]queryconnector.SchemaEntry(nil), entries...)}
	adapter.mu.Unlock()
	provenanceDigest := hashValue("COH-SPLUNK-DISCOVERY-PROVENANCE-V1\x00", struct {
		Capability, Qualification string
		Resources                 []Resource
		Indexes                   IndexInventory
		Fields                    RegisteredFieldInventory
		Receipts                  []CallReceipt
	}{request.CapabilityDigest, adapter.qualification.Digest(), resources, indexes, fields,
		[]CallReceipt{indexReceipt, fieldReceipt}})
	cursor := splunkCursorRecord{requestDigest: splunkSchemaRequestDigest(request), schemaDigest: schemaDigest,
		provenanceDigest: provenanceDigest, entries: entries, issuedAt: now, expiresAt: record.expiresAt}
	return adapter.page(ctx, request, cursor)
}

// Validate compiles the restricted logical SPL profile locally, then submits
// only the resulting canonical candidate to Splunk's non-authorizing v2 parser.
func (adapter *Adapter) Validate(ctx context.Context, query queryconnector.ValidatedQuery) (queryconnector.ValidatedValidation, error) {
	if adapter == nil || query.Digest() == "" {
		return queryconnector.ValidatedValidation{}, invalidInput("splunk_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	value := query.Value()
	if value.Language != "spl" || validateAdapterScope(adapter.config, value.Scope) != nil ||
		validateAuthority(adapter.config, CallBinding{Scope: value.Scope, Authority: value.Authority}) != nil ||
		!validQueryLimits(value.Limits) || exceedsQueryLimits(value.Limits, adapter.config.HardLimits) {
		return adapter.validation(ctx, query, "denied", "splunk_query_binding_invalid", "", "")
	}
	now := adapter.clock.Now().UTC()
	requestedAt, requestedErr := time.Parse(splunkTimestampLayout, value.RequestedAt)
	deadline, deadlineErr := time.Parse(splunkTimestampLayout, value.Deadline)
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	if _, revoked := adapter.revoked[value.Authority.PolicyDecisionDigest]; revoked {
		adapter.mu.Unlock()
		return adapter.validation(ctx, query, "denied", "splunk_authority_revoked", "", "")
	}
	if replay, ok := adapter.validations[query.Digest()]; ok {
		adapter.mu.Unlock()
		return replay.validation, nil
	}
	if bound, ok := adapter.queryIDs[value.QueryID]; ok && bound != query.Digest() {
		adapter.mu.Unlock()
		return adapter.validation(ctx, query, "denied", "splunk_query_replay_conflict", "", "")
	}
	capability, capabilityOK := adapter.capabilities[value.CapabilityDigest]
	schema, schemaOK := adapter.schemas[schemaRecordKey(value.CapabilityDigest, value.SchemaDigest)]
	adapter.mu.Unlock()
	if !capabilityOK || !schemaOK || schema.capabilityDigest != value.CapabilityDigest ||
		!now.Before(capability.expiresAt) || !now.Before(schema.expiresAt) || !slices.Equal(capability.resources, value.Scope.ResourceIDs) {
		return adapter.validation(ctx, query, "denied", "splunk_query_authority_stale", "", "")
	}
	if requestedErr != nil || deadlineErr != nil || requestedAt.After(now) || !now.Before(deadline) || deadline.After(capability.expiresAt) {
		return adapter.validation(ctx, query, "denied", "splunk_query_stale", "", "")
	}
	resource, err := splunkparser.Inspect(ctx, value.NativeText)
	if err != nil {
		return adapter.parserDenial(ctx, query, err)
	}
	if !slices.Contains(value.Scope.ResourceIDs, resource) {
		return adapter.validation(ctx, query, "denied", "splunk_resource_scope_mismatch", "", "")
	}
	definition, err := adapter.parserDefinition(resource, schema.entries)
	if err != nil {
		return adapter.validation(ctx, query, "denied", queryconnector.Reason(err), "", "")
	}
	tenantValue, sourceValue := "", ""
	if definition.TenantField != "" {
		tenantValue = value.Scope.TenantID
	}
	if definition.SourceField != "" {
		sourceValue = value.Scope.SourceID
	}
	candidate, err := splunkparser.Compile(ctx, splunkparser.CompileRequest{Query: value.NativeText, QueryID: value.QueryID,
		Definition: definition, ActorID: value.Authority.ActorID, AuthorizationDigest: value.Authority.AuthorizationDigest,
		PolicyDecisionDigest: value.Authority.PolicyDecisionDigest, AuditReservationDigest: value.Authority.AuditReservationDigest,
		CapabilityDigest: value.CapabilityDigest, SchemaDigest: value.SchemaDigest,
		ScopeDigest: hashValue("COH-SPLUNK-SCOPE-V1\x00", value.Scope), Earliest: value.TimeRange.Start, Latest: value.TimeRange.End,
		MaximumRows: value.Limits.MaximumRows, MaximumBytes: value.Limits.MaximumBytes,
		MaximumDurationMillis: value.Limits.MaximumDurationMillis, MandatoryTenantValue: tenantValue, MandatorySourceValue: sourceValue})
	if err != nil {
		return adapter.parserDenial(ctx, query, err)
	}
	binding := CallBinding{Scope: value.Scope, Authority: value.Authority, Operation: "splunk.parser",
		Targets: append([]string(nil), value.Scope.ResourceIDs...)}
	parsed, receipt, err := adapter.client.ParserPreflight(ctx, ParserRequest{Binding: binding, CanonicalSPL: candidate.CanonicalSPL})
	if err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	if err := validateQualificationReceipt(adapter.config, receipt); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	if !validParserCommands(parsed.Commands, candidate.CanonicalSPL, candidate.CommandCount) {
		return adapter.validation(ctx, query, "denied", "splunk_parser_semantic_drift", "", "")
	}
	receiptDigest := hashValue("COH-SPLUNK-PARSER-RECEIPT-V1\x00", struct {
		Result  ParserResult
		Receipt CallReceipt
	}{parsed, receipt})
	plan, err := splunkparser.BindParserReceipt(candidate, receiptDigest)
	if err != nil {
		return queryconnector.ValidatedValidation{}, deniedCall("splunk_parser_receipt_invalid")
	}
	validation, err := adapter.validation(ctx, query, "accepted", "", plan.QueryDigest, plan.PlanDigest)
	if err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	if _, revoked := adapter.revoked[value.Authority.PolicyDecisionDigest]; revoked {
		adapter.mu.Unlock()
		return adapter.validation(ctx, query, "denied", "splunk_authority_revoked", "", "")
	}
	if bound, ok := adapter.queryIDs[value.QueryID]; ok && bound != query.Digest() {
		adapter.mu.Unlock()
		return adapter.validation(ctx, query, "denied", "splunk_query_replay_conflict", "", "")
	}
	if len(adapter.validations) >= maximumAdapterRecords {
		adapter.mu.Unlock()
		return queryconnector.ValidatedValidation{}, deniedCall("splunk_adapter_capacity_reached")
	}
	adapter.validations[query.Digest()] = splunkValidationRecord{queryID: value.QueryID, validation: validation, plan: plan, expiresAt: deadline}
	adapter.queryIDs[value.QueryID] = query.Digest()
	adapter.mu.Unlock()
	return validation, nil
}

// ApplyRevocation removes any retained plan bound to the revoked policy
// decision and prevents the decision from authorizing a later retry.
func (adapter *Adapter) ApplyRevocation(ctx context.Context, evidence splunkparser.RevocationEvidence) error {
	if adapter == nil {
		return invalidInput("splunk_adapter_required")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	encoded, _ := json.Marshal(evidence)
	validated, err := splunkparser.DecodeRevocationEvidence(encoded)
	if err != nil {
		return invalidInput("splunk_revocation_invalid")
	}
	observed, err := time.Parse(splunkTimestampLayout, validated.ObservedAt)
	if err != nil || observed.After(adapter.clock.Now().UTC()) {
		return invalidInput("splunk_revocation_invalid")
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	existing, exists := adapter.revoked[validated.DecisionDigest]
	if exists && existing != validated.RevocationDigest {
		return conflictCall("splunk_revocation_conflict")
	}
	if !exists && len(adapter.revoked) >= maximumAdapterRecords {
		return deniedCall("splunk_adapter_capacity_reached")
	}
	adapter.revoked[validated.DecisionDigest] = validated.RevocationDigest
	for key, record := range adapter.validations {
		if record.plan.Authority.PolicyDecisionDigest == validated.DecisionDigest &&
			record.plan.Authority.AuditReservationDigest == validated.AuditReservationDigest {
			delete(adapter.validations, key)
			if adapter.queryIDs[record.queryID] == key {
				delete(adapter.queryIDs, record.queryID)
			}
		}
	}
	return nil
}

func (adapter *Adapter) parserDenial(ctx context.Context, query queryconnector.ValidatedQuery, err error) (queryconnector.ValidatedValidation, error) {
	var semantic *splunkparser.ParseError
	if errors.As(err, &semantic) {
		return adapter.validation(ctx, query, "denied", semantic.Reason, "", "")
	}
	return queryconnector.ValidatedValidation{}, err
}

func (adapter *Adapter) validation(ctx context.Context, query queryconnector.ValidatedQuery, outcome, reason, canonical, provenance string) (queryconnector.ValidatedValidation, error) {
	reasons := []string{}
	if reason != "" {
		reasons = []string{reason}
	}
	if provenance == "" {
		provenance = hashValue("COH-SPLUNK-VALIDATION-DENIAL-V1\x00", struct{ Query, Reason string }{query.Digest(), reason})
	}
	if canonical == "" {
		canonical = hashValue("COH-SPLUNK-CANONICAL-QUERY-V1\x00", struct{ Query, Provenance string }{query.Digest(), provenance})
	}
	value := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.Value().QueryID, Outcome: outcome,
		ReasonCodes: reasons, ValidatorVersion: splunkparser.ValidatorVersion,
		CanonicalQueryDigest: canonical, ProvenanceDigest: provenance}
	encoded, _ := json.Marshal(value)
	return queryconnector.DecodeValidation(ctx, encoded)
}

// LoadSchema exposes the same bounded operation to the common schema cache.
func (adapter *Adapter) LoadSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	return adapter.DiscoverSchema(ctx, request)
}

func normalizeIndexes(config Config, resourceIDs []string, inventory IndexInventory) ([]Resource, error) {
	observed := make(map[string]struct{}, len(inventory.Names))
	for _, name := range inventory.Names {
		if !safeIndex(name) {
			return nil, deniedCall("splunk_index_inventory_invalid")
		}
		observed[name] = struct{}{}
	}
	resources := make([]Resource, 0, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		index := slices.IndexFunc(config.Resources, func(value Resource) bool { return value.ID == resourceID })
		if index < 0 {
			return nil, deniedCall("splunk_resource_not_allowed")
		}
		resource := config.Resources[index]
		if _, ok := observed[resource.Index]; !ok {
			return nil, conflictCall("splunk_configured_index_missing")
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func normalizeFields(config Config, resources []Resource, inventory RegisteredFieldInventory) ([]queryconnector.SchemaEntry, error) {
	registered := make(map[string]bool, len(inventory.Fields))
	for _, field := range inventory.Fields {
		if !vendorFieldPattern.MatchString(field.Name) {
			return nil, deniedCall("splunk_field_inventory_invalid")
		}
		if _, exists := registered[field.Name]; exists {
			return nil, deniedCall("splunk_field_inventory_ambiguous")
		}
		registered[field.Name] = field.Indexed
	}
	resourceSet := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		resourceSet[resource.ID] = struct{}{}
	}
	entries := make([]queryconnector.SchemaEntry, 0, len(config.Fields)*len(resources))
	for _, field := range config.Fields {
		indexed, exists := registered[field.VendorName]
		if !exists {
			return nil, conflictCall("splunk_configured_field_missing")
		}
		if field.IndexedRequired && !indexed {
			return nil, queryconnector.NewError(queryconnector.Unsupported, "splunk_field_indexing_conflict", nil)
		}
		for _, resourceID := range field.ResourceIDs {
			if _, selected := resourceSet[resourceID]; selected {
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

func (adapter *Adapter) qualificationExpiry(now time.Time) (time.Time, error) {
	expiresAt, err := time.Parse(splunkTimestampLayout, adapter.qualification.Value().ValidUntil)
	if err != nil || !now.Before(expiresAt) {
		return time.Time{}, deniedCall("splunk_qualification_stale")
	}
	return expiresAt, nil
}

func (adapter *Adapter) admitCapability(request queryconnector.SchemaRequest, now time.Time) (splunkCapabilityRecord, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.removeExpiredLocked(now)
	record, ok := adapter.capabilities[request.CapabilityDigest]
	if !ok || !now.Before(record.expiresAt) {
		return splunkCapabilityRecord{}, deniedCall("splunk_capability_stale")
	}
	if !slices.Equal(record.resources, request.Scope.ResourceIDs) {
		return splunkCapabilityRecord{}, conflictCall("splunk_capability_scope_mismatch")
	}
	return record, nil
}

func (adapter *Adapter) loadCursor(ctx context.Context, request queryconnector.SchemaRequest, now time.Time) (queryconnector.ValidatedSchemaPage, error) {
	provided := *request.Cursor
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	record, ok := adapter.cursors[provided.HandleID]
	adapter.mu.Unlock()
	if !ok || !now.Before(record.expiresAt) {
		return queryconnector.ValidatedSchemaPage{}, deniedCall("splunk_schema_cursor_stale")
	}
	if provided != adapter.cursorHandle(record) || record.requestDigest != splunkSchemaRequestDigest(request) {
		return queryconnector.ValidatedSchemaPage{}, conflictCall("splunk_schema_cursor_mismatch")
	}
	return adapter.page(ctx, request, record)
}

func (adapter *Adapter) page(ctx context.Context, request queryconnector.SchemaRequest, record splunkCursorRecord) (queryconnector.ValidatedSchemaPage, error) {
	if record.offset < 0 || record.offset >= len(record.entries) {
		return queryconnector.ValidatedSchemaPage{}, deniedCall("splunk_schema_cursor_invalid")
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
			NextCursor: next, Complete: complete, ProvenanceDigest: hashValue("COH-SPLUNK-SCHEMA-PAGE-V1\x00", struct {
				Discovery   string
				Offset, End int
			}{record.provenanceDigest, record.offset, end})}
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
				if len(adapter.cursors) >= maximumAdapterRecords {
					adapter.mu.Unlock()
					return queryconnector.ValidatedSchemaPage{}, deniedCall("splunk_adapter_capacity_reached")
				}
				adapter.cursors[next.HandleID] = nextRecord
				adapter.mu.Unlock()
			}
			return validated, nil
		}
		end--
	}
	return queryconnector.ValidatedSchemaPage{}, deniedCall("splunk_schema_page_oversized")
}

func (adapter *Adapter) cursorHandle(record splunkCursorRecord) queryconnector.HandleRef {
	opaque := hashValue("COH-SPLUNK-SCHEMA-CURSOR-V1\x00", struct {
		Request, Schema, Provenance string
		Offset                      int
		ExpiresAt                   string
	}{record.requestDigest, record.schemaDigest, record.provenanceDigest, record.offset, record.expiresAt.Format(splunkTimestampLayout)})
	return queryconnector.HandleRef{HandleID: splunkDeterministicUUID(record.issuedAt, opaque), Kind: "schema_cursor",
		SourceID: adapter.config.SourceID, OpaqueDigest: opaque, IssuedAt: record.issuedAt.Format(splunkTimestampLayout),
		ExpiresAt: record.expiresAt.Format(splunkTimestampLayout)}
}

func (adapter *Adapter) removeExpiredLocked(now time.Time) {
	for key, value := range adapter.capabilities {
		if !now.Before(value.expiresAt) {
			delete(adapter.capabilities, key)
		}
	}
	for key, value := range adapter.cursors {
		if !now.Before(value.expiresAt) {
			delete(adapter.cursors, key)
		}
	}
	for key, value := range adapter.schemas {
		if !now.Before(value.expiresAt) {
			delete(adapter.schemas, key)
		}
	}
	for key, value := range adapter.validations {
		if !now.Before(value.expiresAt) {
			delete(adapter.validations, key)
			if adapter.queryIDs[value.queryID] == key {
				delete(adapter.queryIDs, value.queryID)
			}
		}
	}
}

func (adapter *Adapter) parserDefinition(resourceID string, entries []queryconnector.SchemaEntry) (splunkparser.Definition, error) {
	resourceIndex := slices.IndexFunc(adapter.config.Resources, func(value Resource) bool { return value.ID == resourceID })
	if resourceIndex < 0 {
		return splunkparser.Definition{}, deniedCall("splunk_resource_not_allowed")
	}
	entryTypes := make(map[string]string)
	for _, entry := range entries {
		if entry.ResourceID == resourceID {
			entryTypes[entry.Name] = entry.Type
		}
	}
	fields := make([]splunkparser.FieldRule, 0, len(adapter.config.Fields))
	defaultProjection := make([]string, 0, len(adapter.config.Fields))
	timestamp, tenant, source := "", "", ""
	for _, configured := range adapter.config.Fields {
		if !slices.Contains(configured.ResourceIDs, resourceID) {
			continue
		}
		if entryTypes[configured.SchemaName] != configured.Type {
			return splunkparser.Definition{}, conflictCall("splunk_parser_schema_mismatch")
		}
		sortable := configured.Type != "boolean"
		aggregatable := configured.Type != "boolean" && configured.Type != "timestamp"
		fields = append(fields, splunkparser.FieldRule{Name: configured.SchemaName, VendorName: configured.VendorName,
			Type: configured.Type, Projectable: true, Filterable: true, Sortable: sortable, Aggregatable: aggregatable})
		defaultProjection = append(defaultProjection, configured.SchemaName)
		if timestamp == "" && configured.Type == "timestamp" {
			timestamp = configured.SchemaName
		}
		if configured.SchemaName == "tenant.id" {
			tenant = configured.SchemaName
		}
		if configured.SchemaName == "source.id" {
			source = configured.SchemaName
		}
		delete(entryTypes, configured.SchemaName)
	}
	if timestamp == "" || len(fields) == 0 || len(entryTypes) != 0 {
		return splunkparser.Definition{}, conflictCall("splunk_parser_schema_mismatch")
	}
	definition := splunkparser.Definition{SchemaVersion: splunkparser.DefinitionVersion,
		ContractVersion: splunkparser.ContractVersion, ValidatorVersion: splunkparser.ValidatorVersion,
		SourceID: adapter.config.SourceID, Resources: []splunkparser.ResourceRule{{ID: resourceID,
			VendorIndex: adapter.config.Resources[resourceIndex].Index}}, Fields: fields, DefaultProjection: defaultProjection,
		StableSort: []splunkparser.SortRule{{Name: timestamp, Direction: "desc"}}, TimestampField: timestamp,
		TenantField: tenant, SourceField: source, HardMaximumRows: adapter.config.HardLimits.MaximumRows}
	encoded, _ := json.Marshal(definition)
	return splunkparser.DecodeDefinition(encoded)
}

func validParserCommands(commands []string, canonical string, expected uint32) bool {
	if len(commands) != int(expected) || len(commands) == 0 || commands[0] != "search" {
		return false
	}
	want := map[string]int{
		"search": 1 + strings.Count(canonical, "[ search "),
		"fields": strings.Count(canonical, " | fields "),
		"table":  strings.Count(canonical, " | table "),
		"stats":  strings.Count(canonical, " | stats "),
		"sort":   strings.Count(canonical, " | sort "),
		"head":   strings.Count(canonical, " | head "),
	}
	got := make(map[string]int, len(want))
	for _, command := range commands {
		if _, allowed := want[command]; !allowed {
			return false
		}
		got[command]++
	}
	for command, count := range want {
		if got[command] != count {
			return false
		}
	}
	return true
}

func schemaRecordKey(capability, schema string) string { return capability + "\x00" + schema }

func validateAdapterScope(config Config, scope queryconnector.Scope) error {
	if !uuidV7Pattern.MatchString(scope.OrganizationID) || !uuidV7Pattern.MatchString(scope.TenantID) ||
		!uuidV7Pattern.MatchString(scope.CaseID) || scope.SourceID != config.SourceID ||
		!validNames(scope.ResourceIDs, 1, len(config.Resources)) {
		return deniedCall("splunk_scope_invalid")
	}
	for _, resourceID := range scope.ResourceIDs {
		if !slices.ContainsFunc(config.Resources, func(resource Resource) bool { return resource.ID == resourceID }) {
			return deniedCall("splunk_resource_not_allowed")
		}
	}
	return nil
}

func validateSchemaRequest(config Config, request queryconnector.SchemaRequest) error {
	if !uuidV7Pattern.MatchString(request.RequestID) || !digestPattern.MatchString(request.CapabilityDigest) ||
		!validQueryLimits(request.Limits) || exceedsQueryLimits(request.Limits, config.HardLimits) {
		return invalidInput("splunk_schema_request_invalid")
	}
	binding := CallBinding{Scope: request.Scope, Authority: request.Authority}
	if err := validateAuthority(config, binding); err != nil {
		return err
	}
	return nil
}

func validQueryLimits(value queryconnector.Limits) bool {
	return value.MaximumRows > 0 && value.MaximumBytes > 0 && value.MaximumDurationMillis > 0 && value.MaximumPages > 0 &&
		value.MaximumSlices > 0 && value.MaximumCostMillionths > 0 && value.RequestsPerMinute > 0
}

func exceedsQueryLimits(value, maximum queryconnector.Limits) bool {
	return value.MaximumRows > maximum.MaximumRows || value.MaximumBytes > maximum.MaximumBytes ||
		value.MaximumDurationMillis > maximum.MaximumDurationMillis || value.MaximumPages > maximum.MaximumPages ||
		value.MaximumSlices > maximum.MaximumSlices || value.MaximumCostMillionths > maximum.MaximumCostMillionths ||
		value.RequestsPerMinute > maximum.RequestsPerMinute
}

func splunkSchemaRequestDigest(request queryconnector.SchemaRequest) string {
	request.Cursor = nil
	return hashValue("COH-SPLUNK-SCHEMA-REQUEST-V1\x00", request)
}

func splunkDeterministicUUID(now time.Time, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	millis := uint64(now.UnixMilli()) & ((1 << 48) - 1)
	return fmt.Sprintf("%08x-%04x-7%03x-%04x-%012x", uint32(millis>>16), uint16(millis),
		uint16(sum[0])<<4|uint16(sum[1]>>4), uint16(0x8000)|(uint16(sum[2])<<6)|uint16(sum[3]>>2), sum[4:10])
}
