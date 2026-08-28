package sentinel

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/kustovalidator"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const maximumRuntimeRecords = 4096

type QueryValidationPort interface {
	Validate(context.Context, queryconnector.ValidatedQuery) (kustovalidator.ValidationAdmission, error)
}

type runtimeCapabilityRecord struct {
	baseDigest    string
	bindingDigest string
	expiresAt     time.Time
}

type preparedQuery struct {
	query      queryconnector.ValidatedQuery
	validation queryconnector.ValidatedValidation
	admission  kustovalidator.ValidationAdmission
	expiresAt  time.Time
}

type executionFlight struct {
	done             chan struct{}
	validationDigest string
	execution        queryconnector.ValidatedExecution
	err              error
	expiresAt        time.Time
}

type sentinelQueryJob struct {
	mu sync.Mutex

	query       queryconnector.Query
	queryDigest string
	validation  queryconnector.ValidatedValidation
	admission   kustovalidator.ValidationAdmission
	execution   queryconnector.ValidatedExecution
	request     QueryTransportRequest
	response    QueryTransportResponse
	authority   queryconnector.AuthorityBinding
	expiresAt   time.Time
	canceled    bool
	released    bool
	poll        *queryconnector.ValidatedPoll
}

type QueryRuntime struct {
	discovery *Adapter
	config    QueryRuntimeConfig
	validator QueryValidationPort
	client    QueryClient
	clock     Clock

	mu           sync.Mutex
	capabilities map[string]runtimeCapabilityRecord
	prepared     map[string]preparedQuery
	executions   map[string]*executionFlight
	jobs         map[string]*sentinelQueryJob
}

func NewQueryRuntime(discovery *Adapter, config QueryRuntimeConfig, validator QueryValidationPort,
	client QueryClient, clock Clock) (*QueryRuntime, error) {
	if discovery == nil || nilPort(validator) || nilPort(client) || nilPort(clock) {
		return nil, invalidInput("sentinel_query_runtime_configuration_invalid")
	}
	validated, err := DecodeQueryRuntimeConfig(encodeQueryContract(config))
	if err != nil || validated.DiscoveryConfigDigest != hashValue("COH-SENTINEL-CONFIG-V1\x00", discovery.config) ||
		validated.SplitThresholdRows > discovery.config.HardLimits.MaximumRows ||
		validated.SplitThresholdBytes > discovery.config.HardLimits.MaximumBytes ||
		validated.MaximumResponseBytes > discovery.config.HardLimits.MaximumBytes ||
		!runtimeProfilesMatch(discovery.config, validated.StableKeys) {
		return nil, invalidInput("sentinel_query_runtime_configuration_invalid")
	}
	return &QueryRuntime{discovery: discovery, config: validated, validator: validator, client: client, clock: clock,
		capabilities: make(map[string]runtimeCapabilityRecord), prepared: make(map[string]preparedQuery),
		executions: make(map[string]*executionFlight), jobs: make(map[string]*sentinelQueryJob)}, nil
}

func (runtime *QueryRuntime) Probe(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (queryconnector.ValidatedCapability, error) {
	if runtime == nil || runtime.discovery == nil {
		return queryconnector.ValidatedCapability{}, invalidInput("sentinel_query_runtime_required")
	}
	base, err := runtime.discovery.Probe(ctx, scope, authority)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	now, value := runtime.clock.Now().UTC(), base.Value()
	value.Features.Polling, value.Features.Cancellation, value.Features.Statistics = true, true, true
	value.SourceIdentityDigest = hashValue("COH-SENTINEL-QUERY-SOURCE-IDENTITY-V1\x00", struct {
		Discovery, Runtime string
	}{base.Digest(), runtime.config.Digest})
	value.SnapshotID = sentinelDeterministicUUID(now, value.SourceIdentityDigest)
	encoded, _ := json.Marshal(value)
	capability, err := queryconnector.DecodeCapability(ctx, encoded)
	if err != nil {
		return queryconnector.ValidatedCapability{}, err
	}
	expiresAt, _ := time.Parse(sentinelTimestampLayout, value.ValidUntil)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.removeExpiredLocked(now)
	if _, exists := runtime.capabilities[capability.Digest()]; !exists && len(runtime.capabilities) >= maximumRuntimeRecords {
		return queryconnector.ValidatedCapability{}, deniedCall("sentinel_query_runtime_capacity_reached")
	}
	runtime.capabilities[capability.Digest()] = runtimeCapabilityRecord{baseDigest: base.Digest(),
		bindingDigest: runtime.discovery.bindingDigest(scope, authority), expiresAt: expiresAt}
	return capability, nil
}

func (runtime *QueryRuntime) DiscoverSchema(ctx context.Context,
	request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	if runtime == nil || runtime.discovery == nil {
		return queryconnector.ValidatedSchemaPage{}, invalidInput("sentinel_query_runtime_required")
	}
	now := runtime.clock.Now().UTC()
	record, err := runtime.admitCapability(request.Scope, request.Authority, request.CapabilityDigest, request.Limits, now)
	if err != nil {
		return queryconnector.ValidatedSchemaPage{}, err
	}
	request.CapabilityDigest = record.baseDigest
	return runtime.discovery.DiscoverSchema(ctx, request)
}

func (runtime *QueryRuntime) Validate(ctx context.Context,
	query queryconnector.ValidatedQuery) (queryconnector.ValidatedValidation, error) {
	if runtime == nil || runtime.discovery == nil || nilPort(runtime.validator) || query.Digest() == "" {
		return queryconnector.ValidatedValidation{}, invalidInput("sentinel_query_runtime_required")
	}
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	now, value := runtime.clock.Now().UTC(), query.Value()
	record, err := runtime.admitCapability(value.Scope, value.Authority, value.CapabilityDigest, value.Limits, now)
	if err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	if value.Language != "kql" || value.Scope.SourceID != runtime.discovery.config.SourceID || record.baseDigest == "" {
		return queryconnector.ValidatedValidation{}, deniedCall("sentinel_query_binding_mismatch")
	}
	admission, err := runtime.validator.Validate(ctx, query)
	if err != nil {
		return queryconnector.ValidatedValidation{}, err
	}
	encoded, _ := json.Marshal(admission.Validation)
	validation, err := queryconnector.DecodeValidation(ctx, encoded)
	if err != nil || queryconnector.AdmitExecution(ctx, query, validation) != nil ||
		admission.CanonicalKQL == "" || admission.CanonicalKQLDigest != kustovalidator.CanonicalKQLDigest(admission.CanonicalKQL) ||
		admission.Decision.QueryID != value.QueryID || admission.Decision.ActorID != value.Authority.ActorID ||
		admission.Decision.CapabilityDigest != value.CapabilityDigest || admission.Decision.SchemaDigest != value.SchemaDigest ||
		admission.Decision.PolicyDecisionDigest != value.Authority.PolicyDecisionDigest ||
		admission.Audit.AuditReservationDigest != value.Authority.AuditReservationDigest || admission.Audit.AuditRecordDigest == "" ||
		len(admission.OutputColumns) == 0 {
		return queryconnector.ValidatedValidation{}, conflictCall("sentinel_validation_binding_mismatch")
	}
	expiresAt, parseErr := time.Parse(sentinelTimestampLayout, value.Deadline)
	if parseErr != nil || !now.Before(expiresAt) {
		return queryconnector.ValidatedValidation{}, deniedCall("sentinel_query_stale")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.removeExpiredLocked(now)
	if _, exists := runtime.prepared[query.Digest()]; !exists && len(runtime.prepared) >= maximumRuntimeRecords {
		return queryconnector.ValidatedValidation{}, deniedCall("sentinel_query_runtime_capacity_reached")
	}
	runtime.prepared[query.Digest()] = preparedQuery{query: query, validation: validation,
		admission: cloneValidationAdmission(admission), expiresAt: minTime(expiresAt, record.expiresAt)}
	return validation, nil
}

func (runtime *QueryRuntime) admitCapability(scope queryconnector.Scope, authority queryconnector.AuthorityBinding,
	digest string, limits queryconnector.Limits, now time.Time) (runtimeCapabilityRecord, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.removeExpiredLocked(now)
	record, ok := runtime.capabilities[digest]
	if !ok || !now.Before(record.expiresAt) || record.bindingDigest != runtime.discovery.bindingDigest(scope, authority) ||
		!limitsWithin(limits, runtime.discovery.config.HardLimits) {
		return runtimeCapabilityRecord{}, deniedCall("sentinel_capability_binding_denied")
	}
	return record, nil
}

func (runtime *QueryRuntime) removeExpiredLocked(now time.Time) {
	for key, value := range runtime.capabilities {
		if !now.Before(value.expiresAt) {
			delete(runtime.capabilities, key)
		}
	}
	for key, value := range runtime.prepared {
		if !now.Before(value.expiresAt) {
			delete(runtime.prepared, key)
		}
	}
	for key, value := range runtime.executions {
		if !now.Before(value.expiresAt) {
			delete(runtime.executions, key)
		}
	}
	for key, value := range runtime.jobs {
		if !now.Before(value.expiresAt) {
			delete(runtime.jobs, key)
		}
	}
}

func runtimeProfilesMatch(config Config, profiles []StableKeyProfile) bool {
	resources := make(map[string]Resource, len(config.Resources))
	for _, resource := range config.Resources {
		resources[resource.ID] = resource
	}
	for _, profile := range profiles {
		resource, ok := resources[profile.ResourceID]
		if !ok || profile.TimestampColumn != resource.TimespanColumn {
			return false
		}
	}
	return true
}

func limitsWithin(value, hard queryconnector.Limits) bool {
	return value.MaximumRows <= hard.MaximumRows && value.MaximumBytes <= hard.MaximumBytes &&
		value.MaximumDurationMillis <= hard.MaximumDurationMillis && value.MaximumPages <= hard.MaximumPages &&
		value.MaximumSlices <= hard.MaximumSlices && value.MaximumCostMillionths <= hard.MaximumCostMillionths &&
		value.RequestsPerMinute <= hard.RequestsPerMinute
}

func cloneValidationAdmission(value kustovalidator.ValidationAdmission) kustovalidator.ValidationAdmission {
	value.OutputColumns = slices.Clone(value.OutputColumns)
	return value
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
