package coh.authz

default decision := {"allow": false, "reason_code": "policy_denied", "approval_required": false}

decision := {"allow": true, "reason_code": "policy_allowed", "approval_required": true} if {
	input.schema_version == "coh.policy-input/v1"
	input.manifest.action_tier == "T2"
	input.manifest.operation == "publish_draft"
	input.actor.permissions[_] == "action.request"
	input.runtime.validator_state == "qualified"
}
