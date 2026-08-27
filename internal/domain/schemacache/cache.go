package schemacache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	resourceDigestDomain = "COH-SCHEMA-CACHE-RESOURCE-SCOPE-V1\x00"
	identityDigestDomain = "COH-SCHEMA-CACHE-ENTRY-V1\x00"
	timestampLayout      = "2006-01-02T15:04:05.000000000Z"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

type cacheKey struct {
	organizationID   string
	tenantID         string
	sourceID         string
	resourceDigest   string
	capabilityDigest string
	adapterVersion   string
	schemaVersion    string
}

type entry struct {
	key            cacheKey
	page           queryconnector.ValidatedSchemaPage
	identityDigest string
	cachedAt       time.Time
	expiresAt      time.Time
	bytes          int
	access         uint64
}

type flight struct {
	done        chan struct{}
	key         cacheKey
	request     Request
	invalidated bool
	snapshot    Snapshot
	err         error
}

type Cache struct {
	config Config
	loader Loader
	clock  Clock

	mu         sync.Mutex
	entries    map[cacheKey]entry
	flights    map[cacheKey]*flight
	totalBytes int
	sequence   uint64
}

func New(config Config, loader Loader, clock Clock) (*Cache, error) {
	if config.MaximumEntries <= 0 || config.MaximumTotalBytes <= 0 || config.MaximumEntryBytes <= 0 ||
		config.MaximumEntryBytes > config.MaximumTotalBytes || config.TTL <= 0 || config.LoadTimeout <= 0 ||
		config.MaximumEntries > MaximumConfiguredEntries || config.MaximumTotalBytes > MaximumConfiguredBytes ||
		config.MaximumEntryBytes > queryconnector.MaximumDocumentBytes || config.TTL > MaximumConfiguredTTL ||
		config.LoadTimeout > MaximumLoadTimeout ||
		nilPort(loader) || nilPort(clock) {
		return nil, newError(InvalidInput, "configuration_invalid", nil)
	}
	return &Cache{config: config, loader: loader, clock: clock, entries: make(map[cacheKey]entry),
		flights: make(map[cacheKey]*flight)}, nil
}

func (cache *Cache) Get(ctx context.Context, request Request) (Snapshot, error) {
	if cache == nil {
		return Snapshot{}, newError(InvalidInput, "cache_required", nil)
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	now := cache.clock.Now().UTC()
	key, capabilityExpiry, err := validateRequest(request, now)
	if err != nil {
		return Snapshot{}, err
	}

	cache.mu.Lock()
	cache.removeExpiredLocked(now)
	if cached, found := cache.entries[key]; found {
		cache.sequence++
		cached.access = cache.sequence
		cache.entries[key] = cached
		snapshot := cached.snapshot(true)
		cache.mu.Unlock()
		return snapshot, nil
	}
	if pending, found := cache.flights[key]; found {
		cache.mu.Unlock()
		return wait(ctx, pending)
	}
	pending := &flight{done: make(chan struct{}), key: key, request: request}
	cache.flights[key] = pending
	cache.mu.Unlock()

	go cache.load(pending, capabilityExpiry)
	return wait(ctx, pending)
}

func (cache *Cache) load(pending *flight, capabilityExpiry time.Time) {
	loadContext, cancel := context.WithTimeout(context.Background(), cache.config.LoadTimeout)
	defer cancel()
	page, err := cache.loader.LoadSchema(loadContext, pending.request.SchemaRequest)
	if err != nil {
		cache.finish(pending, Snapshot{}, mapLoaderError(err))
		return
	}
	value := page.Value()
	request := pending.request.SchemaRequest
	if page.Digest() == "" || value.RequestID != request.RequestID || !value.Complete || value.NextCursor != nil {
		cache.finish(pending, Snapshot{}, newError(Denied, "schema_incomplete_or_mismatched", nil))
		return
	}
	allowed := make(map[string]struct{}, len(request.Scope.ResourceIDs))
	for _, resourceID := range request.Scope.ResourceIDs {
		allowed[resourceID] = struct{}{}
	}
	for _, schemaEntry := range value.Entries {
		if _, ok := allowed[schemaEntry.ResourceID]; !ok {
			cache.finish(pending, Snapshot{}, newError(Denied, "schema_scope_widened", nil))
			return
		}
	}
	bytes := len(page.CanonicalBytes())
	if bytes <= 0 || bytes > cache.config.MaximumEntryBytes {
		cache.finish(pending, Snapshot{}, newError(Denied, "schema_entry_too_large", nil))
		return
	}
	now := cache.clock.Now().UTC()
	expiresAt := now.Add(cache.config.TTL)
	if capabilityExpiry.Before(expiresAt) {
		expiresAt = capabilityExpiry
	}
	if !now.Before(expiresAt) {
		cache.finish(pending, Snapshot{}, newError(Denied, "capability_stale", nil))
		return
	}
	identity, identityErr := entryIdentity(pending.key, page, now, expiresAt)
	if identityErr != nil {
		cache.finish(pending, Snapshot{}, identityErr)
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	delete(cache.flights, pending.key)
	if pending.invalidated {
		pending.err = newError(Conflict, "load_invalidated", nil)
		close(pending.done)
		return
	}
	cache.sequence++
	cached := entry{key: pending.key, page: page, identityDigest: identity, cachedAt: now,
		expiresAt: expiresAt, bytes: bytes, access: cache.sequence}
	cache.entries[pending.key] = cached
	cache.totalBytes += bytes
	cache.enforceCapacityLocked(now)
	pending.snapshot = cached.snapshot(false)
	close(pending.done)
}

func (cache *Cache) finish(pending *flight, snapshot Snapshot, err error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	delete(cache.flights, pending.key)
	pending.snapshot, pending.err = snapshot, err
	close(pending.done)
}

func wait(ctx context.Context, pending *flight) (Snapshot, error) {
	select {
	case <-ctx.Done():
		return Snapshot{}, contextError(ctx)
	case <-pending.done:
		if err := contextError(ctx); err != nil {
			return Snapshot{}, err
		}
		return pending.snapshot, pending.err
	}
}

func (cache *Cache) Invalidate(ctx context.Context, target Invalidation) error {
	if cache == nil {
		return newError(InvalidInput, "cache_required", nil)
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if !uuidPattern.MatchString(target.OrganizationID) || !uuidPattern.MatchString(target.TenantID) ||
		!tokenPattern.MatchString(target.SourceID) ||
		(target.CapabilityDigest != "" && !digestPattern.MatchString(target.CapabilityDigest)) ||
		(target.AdapterVersion != "" && !tokenPattern.MatchString(target.AdapterVersion)) ||
		(target.SchemaVersion != "" && target.SchemaVersion != queryconnector.SchemaSchemaVersion) {
		return newError(InvalidInput, "invalidation_invalid", nil)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for key, cached := range cache.entries {
		if target.matches(key) {
			delete(cache.entries, key)
			cache.totalBytes -= cached.bytes
		}
	}
	for key, pending := range cache.flights {
		if target.matches(key) {
			pending.invalidated = true
		}
	}
	return nil
}

func (target Invalidation) matches(key cacheKey) bool {
	return target.OrganizationID == key.organizationID && target.TenantID == key.tenantID && target.SourceID == key.sourceID &&
		(target.CapabilityDigest == "" || target.CapabilityDigest == key.capabilityDigest) &&
		(target.AdapterVersion == "" || target.AdapterVersion == key.adapterVersion) &&
		(target.SchemaVersion == "" || target.SchemaVersion == key.schemaVersion)
}

func (cache *Cache) removeExpiredLocked(now time.Time) {
	for key, cached := range cache.entries {
		if !now.Before(cached.expiresAt) {
			delete(cache.entries, key)
			cache.totalBytes -= cached.bytes
		}
	}
}

func (cache *Cache) enforceCapacityLocked(now time.Time) {
	cache.removeExpiredLocked(now)
	for len(cache.entries) > cache.config.MaximumEntries || cache.totalBytes > cache.config.MaximumTotalBytes {
		var selected cacheKey
		var oldest entry
		found := false
		for key, candidate := range cache.entries {
			if !found || candidate.access < oldest.access ||
				(candidate.access == oldest.access && key.less(selected)) {
				selected, oldest, found = key, candidate, true
			}
		}
		if !found {
			return
		}
		delete(cache.entries, selected)
		cache.totalBytes -= oldest.bytes
	}
}

func (key cacheKey) less(other cacheKey) bool {
	left := []string{key.organizationID, key.tenantID, key.sourceID, key.resourceDigest, key.capabilityDigest, key.adapterVersion, key.schemaVersion}
	right := []string{other.organizationID, other.tenantID, other.sourceID, other.resourceDigest, other.capabilityDigest, other.adapterVersion, other.schemaVersion}
	for index := range left {
		if left[index] != right[index] {
			return left[index] < right[index]
		}
	}
	return false
}

func (cached entry) snapshot(hit bool) Snapshot {
	return Snapshot{page: cached.page, identityDigest: cached.identityDigest, cachedAt: cached.cachedAt,
		expiresAt: cached.expiresAt, hit: hit}
}

func validateRequest(request Request, now time.Time) (cacheKey, time.Time, error) {
	value := request.Capability.Value()
	schema := request.SchemaRequest
	if request.Capability.Digest() == "" || !uuidPattern.MatchString(schema.RequestID) ||
		!validScope(schema.Scope) || !validAuthority(schema.Authority) || schema.Cursor != nil ||
		!validLimits(schema.Limits) || !digestPattern.MatchString(schema.CapabilityDigest) ||
		schema.CapabilityDigest != request.Capability.Digest() || value.SourceID != schema.Scope.SourceID ||
		!value.Features.ReadOnly || !value.Features.SchemaDiscovery {
		return cacheKey{}, time.Time{}, newError(InvalidInput, "request_invalid", nil)
	}
	observedAt, observedErr := time.Parse(timestampLayout, value.ObservedAt)
	validUntil, expiryErr := time.Parse(timestampLayout, value.ValidUntil)
	if observedErr != nil || expiryErr != nil || now.Before(observedAt) {
		return cacheKey{}, time.Time{}, newError(Denied, "capability_not_current", nil)
	}
	if !now.Before(validUntil) {
		return cacheKey{}, time.Time{}, newError(Denied, "capability_stale", nil)
	}
	resourceDigest, err := digestValue(resourceDigestDomain, schema.Scope.ResourceIDs)
	if err != nil {
		return cacheKey{}, time.Time{}, err
	}
	return cacheKey{organizationID: schema.Scope.OrganizationID, tenantID: schema.Scope.TenantID,
		sourceID: schema.Scope.SourceID, resourceDigest: resourceDigest, capabilityDigest: request.Capability.Digest(),
		adapterVersion: value.AdapterVersion, schemaVersion: queryconnector.SchemaSchemaVersion}, validUntil, nil
}

func validScope(scope queryconnector.Scope) bool {
	return uuidPattern.MatchString(scope.OrganizationID) && uuidPattern.MatchString(scope.TenantID) &&
		uuidPattern.MatchString(scope.CaseID) && tokenPattern.MatchString(scope.SourceID) &&
		len(scope.ResourceIDs) > 0 && len(scope.ResourceIDs) <= 4096 && slices.IsSorted(scope.ResourceIDs) &&
		!slices.ContainsFunc(scope.ResourceIDs, func(value string) bool { return !tokenPattern.MatchString(value) }) &&
		!hasDuplicate(scope.ResourceIDs)
}

func validAuthority(authority queryconnector.AuthorityBinding) bool {
	return uuidPattern.MatchString(authority.ActorID) && digestPattern.MatchString(authority.AuthorizationDigest) &&
		digestPattern.MatchString(authority.PolicyDecisionDigest) && digestPattern.MatchString(authority.AuditReservationDigest)
}

func validLimits(limits queryconnector.Limits) bool {
	return limits.MaximumRows > 0 && limits.MaximumBytes > 0 && limits.MaximumDurationMillis > 0 &&
		limits.MaximumPages > 0 && limits.MaximumSlices > 0 && limits.MaximumCostMillionths > 0 && limits.RequestsPerMinute > 0
}

func hasDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func entryIdentity(key cacheKey, page queryconnector.ValidatedSchemaPage, cachedAt, expiresAt time.Time) (string, error) {
	value := page.Value()
	record := struct {
		ContractVersion  string `json:"contract_version"`
		OrganizationID   string `json:"organization_id"`
		TenantID         string `json:"tenant_id"`
		SourceID         string `json:"source_id"`
		ResourceDigest   string `json:"resource_digest"`
		CapabilityDigest string `json:"capability_digest"`
		AdapterVersion   string `json:"adapter_version"`
		SchemaVersion    string `json:"schema_version"`
		PageDigest       string `json:"page_digest"`
		VendorSchema     string `json:"vendor_schema_digest"`
		ProvenanceDigest string `json:"provenance_digest"`
		CachedAt         string `json:"cached_at"`
		ExpiresAt        string `json:"expires_at"`
	}{ContractVersion, key.organizationID, key.tenantID, key.sourceID, key.resourceDigest, key.capabilityDigest,
		key.adapterVersion, key.schemaVersion, page.Digest(), value.SchemaDigest, value.ProvenanceDigest,
		cachedAt.Format(timestampLayout), expiresAt.Format(timestampLayout)}
	return digestValue(identityDigestDomain, record)
}

func digestValue(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", newError(Internal, "canonicalization_failed", err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(Internal, "canonicalization_failed", err)
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return slices.Contains([]reflect.Kind{reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice}, reflected.Kind()) && reflected.IsNil()
}
