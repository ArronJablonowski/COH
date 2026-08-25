package secretresolver

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

func New(backends []Backend, audit AuditSink, replay ReplayStore) (*Resolver, error) {
	if len(backends) == 0 || audit == nil || replay == nil {
		return nil, resolverError(secretref.InvalidInput, "resolver_configuration_invalid")
	}
	registry := make(map[string]Backend, len(backends))
	for _, backend := range backends {
		if backend == nil || !validBackendName(backend.Name()) {
			return nil, resolverError(secretref.InvalidInput, "backend_invalid")
		}
		if _, exists := registry[backend.Name()]; exists {
			return nil, resolverError(secretref.Conflict, "backend_conflict")
		}
		registry[backend.Name()] = backend
	}
	return &Resolver{backends: registry, audit: audit, replay: replay}, nil
}

func (resolver *Resolver) Resolve(ctx context.Context, request secretref.ResolutionRequest) (*Secret, secretref.Decision, error) {
	if resolver == nil || resolver.audit == nil || resolver.replay == nil {
		err := resolverError(secretref.Unavailable, "resolver_unavailable")
		return nil, decisionFor(request, err, 0, false), err
	}
	if err := contextError(ctx); err != nil {
		return resolver.record(ctx, request, nil, err, 0, false)
	}
	if err := secretref.ValidateResolutionRequest(request); err != nil {
		return resolver.record(ctx, request, nil, err, 0, false)
	}
	backend, exists := resolver.backends[request.Reference.Backend]
	if !exists {
		err := resolverError(secretref.Denied, "backend_not_approved")
		return resolver.record(ctx, request, nil, err, 0, false)
	}
	record, err := backend.Fetch(ctx, request.Reference)
	if err != nil {
		resultErr := resolverError(secretref.Unavailable, "backend_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = resolverError(secretref.Denied, "reference_not_found")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		zero(record.Value)
		return resolver.record(ctx, request, nil, resultErr, 0, false)
	}
	value := record.Value
	record.Value = nil
	if err := validateRecord(record, value); err != nil {
		return resolver.record(ctx, request, value, err, record.Revision, false)
	}
	if !record.Active {
		err := resolverError(secretref.Denied, "secret_revoked")
		return resolver.record(ctx, request, value, err, record.Revision, false)
	}
	if record.Backend != request.Reference.Backend || record.EntryID != request.Reference.EntryID {
		err := resolverError(secretref.Denied, "reference_mismatch")
		return resolver.record(ctx, request, value, err, record.Revision, false)
	}
	if record.Version != request.Reference.Version {
		err := resolverError(secretref.Denied, "stale_reference")
		return resolver.record(ctx, request, value, err, record.Revision, false)
	}
	if record.OrganizationID != request.Context.OrganizationID || record.TenantID != request.Context.TenantID ||
		record.CredentialClass != request.CredentialClass || !caseAllowed(record, request.Context.CaseID) {
		err := resolverError(secretref.Denied, "secret_scope_denied")
		return resolver.record(ctx, request, value, err, record.Revision, false)
	}
	requestDigest, _ := secretref.RequestDigest(request)
	replay, err := resolver.replay.CheckAndStore(ctx, ReplayRecord{
		OrganizationID: request.Context.OrganizationID, ActorID: request.Context.ActorID,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: requestDigest,
	})
	if err != nil {
		resultErr := resolverError(secretref.Unavailable, "replay_store_unavailable")
		if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return resolver.record(ctx, request, value, resultErr, record.Revision, false)
	}
	switch replay {
	case ReplayNew:
		return resolver.record(ctx, request, value, nil, record.Revision, false)
	case ReplayExact:
		return resolver.record(ctx, request, value, nil, record.Revision, true)
	case ReplayConflict:
		err := resolverError(secretref.Conflict, "idempotency_conflict")
		return resolver.record(ctx, request, value, err, record.Revision, false)
	default:
		err := resolverError(secretref.Unavailable, "replay_store_unavailable")
		return resolver.record(ctx, request, value, err, record.Revision, false)
	}
}

func (resolver *Resolver) record(
	ctx context.Context,
	request secretref.ResolutionRequest,
	value []byte,
	resultErr error,
	revision uint64,
	replayed bool,
) (*Secret, secretref.Decision, error) {
	decision := decisionFor(request, resultErr, revision, replayed)
	if err := resolver.audit.AppendSecretDecision(ctx, decision); err != nil {
		zero(value)
		auditErr := resolverError(secretref.Unavailable, "audit_unavailable")
		return nil, decisionFor(request, auditErr, revision, false), auditErr
	}
	if resultErr != nil {
		zero(value)
		return nil, decision, resultErr
	}
	return newSecret(value), decision, nil
}

func decisionFor(request secretref.ResolutionRequest, err error, revision uint64, replayed bool) secretref.Decision {
	if err == nil {
		return secretref.NewDecision(request, "allowed", "secret_scope_allowed", revision, replayed)
	}
	outcome := "unavailable"
	switch secretref.Code(err) {
	case secretref.InvalidInput:
		outcome = "invalid"
	case secretref.Denied, secretref.Conflict:
		outcome = "denied"
	case secretref.Canceled:
		outcome = "canceled"
	case secretref.Timeout:
		outcome = "timeout"
	}
	return secretref.NewDecision(request, outcome, reason(err), revision, replayed)
}

func validateRecord(record Record, value []byte) error {
	if !validBackendName(record.Backend) || !validToken(record.EntryID) || record.Version == 0 || record.Revision == 0 ||
		!validUUID(record.OrganizationID) || !validUUID(record.TenantID) || !validToken(record.CredentialClass) ||
		len(value) == 0 || len(value) > maximumSecretBytes || !validCaseGrant(record) {
		return resolverError(secretref.Denied, "backend_record_invalid")
	}
	return nil
}

func validCaseGrant(record Record) bool {
	if record.AllCases {
		return len(record.CaseIDs) == 0
	}
	if len(record.CaseIDs) == 0 || !slices.IsSorted(record.CaseIDs) {
		return false
	}
	for index, caseID := range record.CaseIDs {
		if !validUUID(caseID) || (index > 0 && record.CaseIDs[index-1] == caseID) {
			return false
		}
	}
	return true
}

func caseAllowed(record Record, caseID string) bool {
	return record.AllCases || slices.Contains(record.CaseIDs, caseID)
}

func validBackendName(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[14] != '7' || !strings.Contains("89ab", value[19:20]) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
