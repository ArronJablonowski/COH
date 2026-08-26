package broker

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

func validateActor(actor policy.ActorAuthority, organizationID, tenantID, caseID, permission string) error {
	if !uuidPattern.MatchString(actor.ActorID) || !uuidPattern.MatchString(actor.OrganizationID) ||
		!uuidPattern.MatchString(actor.TenantID) || !uuidPattern.MatchString(actor.CaseID) || actor.Revision == 0 {
		return lifecycle.NewError(lifecycle.InvalidInput, "actor_authority")
	}
	if actor.OrganizationID != organizationID || actor.TenantID != tenantID || actor.CaseID != caseID {
		return lifecycle.NewError(lifecycle.Denied, "actor_scope_mismatch")
	}
	if !actor.Active {
		return lifecycle.NewError(lifecycle.Denied, "actor_revoked")
	}
	if !sortedUniqueTokens(actor.Roles) || !sortedUniqueTokens(actor.Permissions) {
		return lifecycle.NewError(lifecycle.InvalidInput, "actor_authority")
	}
	if !contains(actor.Permissions, permission) {
		return lifecycle.NewError(lifecycle.Denied, "permission_denied")
	}
	return nil
}

func validCommand(approvalID, idempotencyKey, reasonCode string, expectedRevision uint64) error {
	if !uuidPattern.MatchString(approvalID) || expectedRevision == 0 || !tokenPattern.MatchString(reasonCode) ||
		!utf8.ValidString(idempotencyKey) || len(idempotencyKey) == 0 || len(idempotencyKey) > 256 || strings.TrimSpace(idempotencyKey) != idempotencyKey {
		return lifecycle.NewError(lifecycle.InvalidInput, "command_invalid")
	}
	return nil
}

func sortedUniqueTokens(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func contains(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}
