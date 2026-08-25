package localidentity

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var (
	uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func ValidateActor(actor Actor) error {
	if actor.SchemaVersion != SchemaVersion || actor.ContractVersion != ContractVersion {
		return identityError(InvalidInput, "unsupported_contract", nil)
	}
	if !uuidV7Pattern.MatchString(actor.ID) || !uuidV7Pattern.MatchString(actor.OrganizationID) || !tokenPattern.MatchString(actor.Name) || actor.Revision == 0 {
		return identityError(InvalidInput, "actor_identity", nil)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(actor.PublicKey)
	if err != nil || len(publicKey) != 32 {
		return identityError(InvalidInput, "actor_public_key", nil)
	}
	if len(actor.Roles) == 0 || len(actor.Roles) > 5 || !sortedUniqueRoles(actor.Roles) {
		return identityError(InvalidInput, "actor_roles", nil)
	}
	if hasRole(actor.Roles, Service) && len(actor.Roles) != 1 {
		return identityError(Denied, "service_role_mixed", nil)
	}
	if len(actor.Grants) == 0 || len(actor.Grants) > 64 || !validGrants(actor.Grants) {
		return identityError(InvalidInput, "actor_grants", nil)
	}
	return nil
}

func ValidateRequest(request Request) error {
	if request.SchemaVersion != SchemaVersion || request.ContractVersion != ContractVersion {
		return identityError(InvalidInput, "unsupported_contract", nil)
	}
	if !uuidV7Pattern.MatchString(request.RequestID) || !validContext(request.Context) ||
		!validOpaque(request.IdempotencyKey, 1, 128) || !digestPattern.MatchString(request.PayloadDigest) {
		return identityError(InvalidInput, "request_identity", nil)
	}
	if request.Channel != API && request.Channel != CLI {
		return identityError(InvalidInput, "request_channel", nil)
	}
	if !knownPermission(request.Permission) {
		return identityError(Denied, "unknown_permission", nil)
	}
	if request.Permission == ActionRequest {
		if !knownTier(request.ActionTier) {
			return identityError(InvalidInput, "action_tier_required", nil)
		}
	} else if request.Permission == ApprovalDecide {
		if request.ActionTier != T2 && request.ActionTier != T3 && request.ActionTier != T4 {
			return identityError(InvalidInput, "approval_tier", nil)
		}
	} else if request.ActionTier != "" {
		return identityError(InvalidInput, "unexpected_action_tier", nil)
	}
	return nil
}

func validContext(value Context) bool {
	return uuidV7Pattern.MatchString(value.OrganizationID) && uuidV7Pattern.MatchString(value.TenantID) &&
		uuidV7Pattern.MatchString(value.CaseID) && uuidV7Pattern.MatchString(value.ActorID)
}

func validGrants(grants []ScopeGrant) bool {
	previousTenant := ""
	for _, grant := range grants {
		if !uuidV7Pattern.MatchString(grant.TenantID) || grant.TenantID <= previousTenant || len(grant.CaseIDs) > 256 {
			return false
		}
		if grant.AllCases == (len(grant.CaseIDs) != 0) || (!grant.AllCases && len(grant.CaseIDs) == 0) || !sortedUniqueUUIDs(grant.CaseIDs) {
			return false
		}
		previousTenant = grant.TenantID
	}
	return true
}

func sortedUniqueRoles(roles []Role) bool {
	previous := Role("")
	for _, role := range roles {
		if !knownRole(role) || role <= previous {
			return false
		}
		previous = role
	}
	return true
}

func sortedUniqueUUIDs(values []string) bool {
	previous := ""
	for _, value := range values {
		if !uuidV7Pattern.MatchString(value) || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.ToValidUTF8(value, "") == value && !strings.ContainsAny(value, "\r\n\t")
}

func knownRole(value Role) bool {
	return value == Administrator || value == Analyst || value == Approver || value == Auditor || value == Service
}

func knownPermission(value Permission) bool {
	for _, permission := range allPermissions {
		if value == permission {
			return true
		}
	}
	return false
}

func knownTier(value ActionTier) bool {
	return value == T0 || value == T1 || value == T2 || value == T3 || value == T4
}

func hasRole(roles []Role, wanted Role) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}
