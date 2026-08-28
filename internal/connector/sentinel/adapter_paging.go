package sentinel

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (adapter *Adapter) admitCapability(request queryconnector.SchemaRequest,
	now time.Time) (sentinelCapabilityRecord, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.removeExpiredLocked(now)
	record, ok := adapter.capabilities[request.CapabilityDigest]
	if !ok || !now.Before(record.expiresAt) {
		return sentinelCapabilityRecord{}, deniedCall("sentinel_capability_stale")
	}
	if record.bindingDigest != adapter.bindingDigest(request.Scope, request.Authority) {
		return sentinelCapabilityRecord{}, conflictCall("sentinel_capability_binding_mismatch")
	}
	return record, nil
}

func (adapter *Adapter) schemaFlight(key string, now, expiresAt time.Time) (*sentinelSchemaFlight, bool,
	queryconnector.ValidatedSchemaPage, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.removeExpiredLocked(now)
	if replay, ok := adapter.replays[key]; ok && now.Before(replay.expiresAt) {
		return nil, false, replay.page, nil
	}
	if flight, ok := adapter.flights[key]; ok {
		return flight, false, queryconnector.ValidatedSchemaPage{}, nil
	}
	if len(adapter.flights) >= maximumAdapterRecords {
		return nil, false, queryconnector.ValidatedSchemaPage{}, deniedCall("sentinel_adapter_capacity_reached")
	}
	flight := &sentinelSchemaFlight{done: make(chan struct{}), expiresAt: expiresAt}
	adapter.flights[key] = flight
	return flight, true, queryconnector.ValidatedSchemaPage{}, nil
}

func (adapter *Adapter) waitSchemaFlight(ctx context.Context,
	flight *sentinelSchemaFlight) (queryconnector.ValidatedSchemaPage, error) {
	select {
	case <-ctx.Done():
		return queryconnector.ValidatedSchemaPage{}, contextError(ctx)
	case <-flight.done:
		if err := contextError(ctx); err != nil {
			return queryconnector.ValidatedSchemaPage{}, err
		}
		return flight.page, flight.err
	}
}

func (adapter *Adapter) finishSchemaFlight(key string, flight *sentinelSchemaFlight,
	page queryconnector.ValidatedSchemaPage, err error) {
	adapter.mu.Lock()
	flight.page, flight.err = page, err
	if err == nil && len(adapter.replays) < maximumAdapterRecords {
		adapter.replays[key] = sentinelSchemaReplay{page: page, expiresAt: flight.expiresAt}
	}
	delete(adapter.flights, key)
	close(flight.done)
	adapter.mu.Unlock()
}

func (adapter *Adapter) loadCursor(ctx context.Context, request queryconnector.SchemaRequest,
	now time.Time) (queryconnector.ValidatedSchemaPage, error) {
	provided := *request.Cursor
	adapter.mu.Lock()
	adapter.removeExpiredLocked(now)
	record, ok := adapter.cursors[provided.HandleID]
	adapter.mu.Unlock()
	if !ok || !now.Before(record.expiresAt) {
		return queryconnector.ValidatedSchemaPage{}, deniedCall("sentinel_schema_cursor_stale")
	}
	if provided != adapter.cursorHandle(record) || record.requestDigest != sentinelSchemaRequestDigest(request) {
		return queryconnector.ValidatedSchemaPage{}, conflictCall("sentinel_schema_cursor_mismatch")
	}
	return adapter.page(ctx, request, record)
}

func (adapter *Adapter) page(ctx context.Context, request queryconnector.SchemaRequest,
	record sentinelCursorRecord) (queryconnector.ValidatedSchemaPage, error) {
	if record.offset < 0 || record.offset >= len(record.entries) {
		return queryconnector.ValidatedSchemaPage{}, deniedCall("sentinel_schema_cursor_invalid")
	}
	end := min(record.offset+int(adapter.config.MaximumSchemaEntriesPerPage), len(record.entries))
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
			NextCursor: next, Complete: complete, ProvenanceDigest: hashValue("COH-SENTINEL-SCHEMA-PAGE-V1\x00", struct {
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
				if _, exists := adapter.cursors[next.HandleID]; !exists && len(adapter.cursors) >= maximumAdapterRecords {
					adapter.mu.Unlock()
					return queryconnector.ValidatedSchemaPage{}, deniedCall("sentinel_adapter_capacity_reached")
				}
				adapter.cursors[next.HandleID] = nextRecord
				adapter.mu.Unlock()
			}
			return validated, nil
		}
		end--
	}
	return queryconnector.ValidatedSchemaPage{}, deniedCall("sentinel_schema_page_oversized")
}

func (adapter *Adapter) cursorHandle(record sentinelCursorRecord) queryconnector.HandleRef {
	opaque := hashValue("COH-SENTINEL-SCHEMA-CURSOR-V1\x00", struct {
		Request, Schema, Provenance string
		Offset                      int
		ExpiresAt                   string
	}{record.requestDigest, record.schemaDigest, record.provenanceDigest, record.offset,
		record.expiresAt.Format(sentinelTimestampLayout)})
	return queryconnector.HandleRef{HandleID: sentinelDeterministicUUID(record.issuedAt, opaque), Kind: "schema_cursor",
		SourceID: adapter.config.SourceID, OpaqueDigest: opaque, IssuedAt: record.issuedAt.Format(sentinelTimestampLayout),
		ExpiresAt: record.expiresAt.Format(sentinelTimestampLayout)}
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
	for key, value := range adapter.replays {
		if !now.Before(value.expiresAt) {
			delete(adapter.replays, key)
		}
	}
}

func validateAdapterScope(config Config, scope queryconnector.Scope) error {
	if !uuidV7Pattern.MatchString(scope.OrganizationID) || !uuidV7Pattern.MatchString(scope.TenantID) ||
		!uuidV7Pattern.MatchString(scope.CaseID) || scope.SourceID != config.SourceID ||
		!validNames(scope.ResourceIDs, 1, len(config.Resources)) {
		return deniedCall("sentinel_scope_invalid")
	}
	for _, resourceID := range scope.ResourceIDs {
		if !slices.ContainsFunc(config.Resources, func(resource Resource) bool { return resource.ID == resourceID }) {
			return deniedCall("sentinel_resource_not_allowed")
		}
	}
	return nil
}

func validateSchemaRequest(config Config, request queryconnector.SchemaRequest) error {
	if !uuidV7Pattern.MatchString(request.RequestID) || !digestPattern.MatchString(request.CapabilityDigest) ||
		!validQueryLimits(request.Limits) || exceedsQueryLimits(request.Limits, config.HardLimits) {
		return invalidInput("sentinel_schema_request_invalid")
	}
	if err := validateAdapterScope(config, request.Scope); err != nil {
		return err
	}
	binding := CallBinding{Scope: request.Scope, Authority: request.Authority, Operation: "sentinel.metadata.get",
		Targets: append([]string(nil), request.Scope.ResourceIDs...), TenantID: config.TenantID, Audience: config.TokenAudience,
		Endpoint: config.Endpoint, TransportIdentityDigest: config.TransportIdentityDigest}
	return validateCallBinding(config, binding)
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

func sentinelSchemaRequestDigest(request queryconnector.SchemaRequest) string {
	request.Cursor = nil
	return hashValue("COH-SENTINEL-SCHEMA-REQUEST-V1\x00", request)
}
