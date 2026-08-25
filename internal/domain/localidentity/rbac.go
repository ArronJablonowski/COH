package localidentity

var allPermissions = []Permission{
	ActionRequest, ApprovalDecide, AuditRead, CaseRead, CaseWrite,
	ConfigurationManage, EvidenceRead, EvidenceWrite, IdentityManage,
	QueryExecute, ServiceInvoke, WorkflowManage,
}

var rolePermissions = map[Role]map[Permission]bool{
	Analyst: {
		ActionRequest: true, CaseRead: true, CaseWrite: true, EvidenceRead: true,
		EvidenceWrite: true, QueryExecute: true, WorkflowManage: true,
	},
	Approver: {ApprovalDecide: true, CaseRead: true, EvidenceRead: true},
	Administrator: {
		AuditRead: true, CaseRead: true, ConfigurationManage: true, IdentityManage: true,
	},
	Auditor: {AuditRead: true, CaseRead: true, EvidenceRead: true},
	Service: {CaseRead: true, EvidenceRead: true, ServiceInvoke: true},
}

// EvaluateRBAC returns a digest-bound decision. It does not authenticate the
// actor or persist audit; the authenticated transport guard must do both.
func EvaluateRBAC(actor Actor, request Request) (Decision, error) {
	decision := decisionFor(actor, request)
	if err := ValidateActor(actor); err != nil {
		decision.Outcome = "denied"
		decision.ReasonCode = "actor_invalid"
		return finalizeDecision(decision), identityError(Denied, "actor_invalid", nil)
	}
	if err := ValidateRequest(request); err != nil {
		decision.Outcome = "invalid"
		if Code(err) == Denied {
			decision.Outcome = "denied"
		}
		decision.ReasonCode = errorReason(err)
		return finalizeDecision(decision), err
	}
	if !actor.Active {
		decision.Outcome = "denied"
		decision.ReasonCode = "actor_revoked"
		return finalizeDecision(decision), identityError(Denied, "actor_revoked", nil)
	}
	if actor.ID != request.Context.ActorID || actor.OrganizationID != request.Context.OrganizationID {
		decision.Outcome = "denied"
		decision.ReasonCode = "identity_scope_mismatch"
		return finalizeDecision(decision), identityError(Denied, "identity_scope_mismatch", nil)
	}
	if !scopeAllows(actor.Grants, request.Context.TenantID, request.Context.CaseID) {
		decision.Outcome = "denied"
		decision.ReasonCode = "case_scope_denied"
		return finalizeDecision(decision), identityError(Denied, "case_scope_denied", nil)
	}
	if !rolesAllow(actor.Roles, request.Permission) {
		decision.Outcome = "denied"
		decision.ReasonCode = "role_permission_denied"
		return finalizeDecision(decision), identityError(Denied, "role_permission_denied", nil)
	}
	decision.Outcome = "allowed"
	decision.ReasonCode = "role_scope_allowed"
	return finalizeDecision(decision), nil
}

func rolesAllow(roles []Role, permission Permission) bool {
	for _, role := range roles {
		if rolePermissions[role][permission] {
			return true
		}
	}
	return false
}

func scopeAllows(grants []ScopeGrant, tenantID, caseID string) bool {
	for _, grant := range grants {
		if grant.TenantID != tenantID {
			continue
		}
		if grant.AllCases {
			return true
		}
		for _, grantedCase := range grant.CaseIDs {
			if grantedCase == caseID {
				return true
			}
		}
	}
	return false
}
