package replayeval

import "reflect"

var allowedBoundaries = map[string]bool{
	"workflow.before_start": true, "workflow.after_start_before_ack": true,
	"workflow.before_signal": true, "workflow.after_signal_before_ack": true,
	"workflow.before_query": true, "workflow.after_query_before_response": true,
	"workflow.before_cancel": true, "workflow.after_cancel_before_ack": true,
	"workflow.before_replay": true, "workflow.history_replay": true,
	"workflow.after_replay_before_response": true, "storage.before_transaction_commit": true,
	"storage.after_transaction_commit_before_ack": true, "outbox.before_lease_commit": true,
	"outbox.after_lease_before_delivery": true, "action.prepared_to_executing": true,
	"action.planned_to_policy_checked": true, "action.policy_checked_to_awaiting_approval": true,
	"action.awaiting_approval_to_prepared": true, "action.executing_to_confirmation_pending": true,
	"action.after_dispatch_before_receipt": true, "action.receipt_before_confirmation_persist": true,
	"action.confirmation_pending_to_verified": true, "action.confirmation_pending_to_compensated": true,
	"action.confirmation_pending_to_uncertain":  true,
	"action.after_confirmation_before_response": true, "action.before_dispatch_cancel": true,
	"action.after_dispatch_cancel": true, "action.policy_checked": true,
	"action.uncertain_reconciliation": true,
}

func simulate(mode string) (Observed, []string, bool) {
	result := Observed{Replayed: true}
	events := []string{"load_durable_state", "inject_fault", "restart_control_plane"}
	switch mode {
	case "workflow_resume":
		result.State, events = "running", append(events, "resume_history")
	case "workflow_idempotent_ack":
		result.State, events = "running", append(events, "find_existing_execution", "return_original_handle")
	case "workflow_idempotent_signal":
		result.State, events = "running", append(events, "deduplicate_signal", "preserve_sequence")
	case "workflow_read_only":
		result.State, events = "running", append(events, "reissue_read_only_query")
	case "workflow_idempotent_cancel":
		result.State, events = "cancelled", append(events, "replay_cancel", "preserve_terminal_state")
	case "workflow_history_replay":
		result.State, events = "completed", append(events, "replay_retained_history", "match_terminal_snapshot")
	case "storage_safe_retry":
		result.State, events = "committed", append(events, "observe_no_commit", "retry_idempotency_key", "commit_once")
	case "storage_commit_replay":
		result.State, events = "committed", append(events, "find_idempotency_result", "return_original_commit")
	case "outbox_safe_reclaim":
		result.State, events = "leased", append(events, "observe_no_lease", "claim_once")
	case "outbox_expired_reclaim":
		result.State, events = "leased", append(events, "wait_for_lease_expiry", "replace_lease_once")
	case "action_safe_predispatch_retry":
		result.State, result.Dispatches, result.ExternalEffects, result.ConfirmedEffects = "verified", 1, 1, 1
		events = append(events, "prove_not_dispatched", "dispatch_once", "persist_confirmation")
	case "action_indeterminate":
		result.State, result.Dispatches, result.ExternalEffects = "uncertain", 1, 1
		result.RequiresReconciliation = true
		events = append(events, "freeze_automatic_retry", "persist_uncertain", "require_reconciliation")
	case "action_receipt_reconcile":
		result.State, result.Dispatches, result.ExternalEffects, result.ConfirmedEffects = "verified", 1, 1, 1
		result.RequiresReconciliation = true
		events = append(events, "freeze_automatic_retry", "reconcile_receipt", "persist_confirmation")
	case "action_confirmed_replay":
		result.State, result.Dispatches, result.ExternalEffects, result.ConfirmedEffects = "verified", 1, 1, 1
		events = append(events, "load_confirmation", "return_without_dispatch")
	case "action_cancel_predispatch":
		result.State = "cancelled"
		events = append(events, "persist_cancelled", "deny_dispatch")
	case "action_cancel_indeterminate":
		result.State, result.Dispatches, result.ExternalEffects = "uncertain", 1, 1
		result.RequiresReconciliation = true
		events = append(events, "request_connector_cancel", "freeze_automatic_retry", "require_reconciliation")
	case "action_denied":
		result.State = "denied"
		events = append(events, "persist_denial", "deny_dispatch")
	case "action_reconcile_no_effect":
		result.State, result.Dispatches = "compensated", 1
		result.RequiresReconciliation = true
		events = append(events, "freeze_automatic_retry", "reconcile_no_effect", "persist_compensated")
	default:
		return Observed{}, nil, false
	}
	return result, events, true
}

func gradeTrajectory(observed Observed, events []string) bool {
	if observed.Dispatches > 1 || observed.ConfirmedEffects > 1 || observed.ConfirmedEffects > observed.ExternalEffects || !observed.Replayed {
		return false
	}
	if observed.State == "verified" && observed.ConfirmedEffects != 1 && observed.Dispatches != 0 {
		return false
	}
	if observed.State == "uncertain" && (!observed.RequiresReconciliation || observed.ConfirmedEffects != 0) {
		return false
	}
	return len(events) >= 4
}

func gradeOutcome(want, got Observed) bool { return reflect.DeepEqual(want, got) }
