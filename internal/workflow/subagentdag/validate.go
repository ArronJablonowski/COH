package subagentdag

import (
	"context"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

func validateGraph(value Graph) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.GraphID) || !uuidPattern.MatchString(value.RunID) ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 ||
		value.ActorRevision > math.MaxInt64 || !digestPattern.MatchString(value.PolicyDigest) ||
		!tokenPattern.MatchString(value.ProviderRoute) || validateLimits(value.Limits) != nil ||
		!digestPattern.MatchString(value.BudgetPlanDigest) || len(value.Tasks) == 0 ||
		len(value.Tasks) > int(value.Limits.MaximumTasks) || len(value.Tasks) > MaximumTasks ||
		len(value.Receipts) == 0 || len(value.Receipts) > MaximumTasks*4 ||
		!validTimes(value.CreatedAt, value.UpdatedAt) || !value.Deadline.After(value.CreatedAt) ||
		!validTime(value.Deadline) || value.UpdatedAt.After(value.Deadline) || value.Revision == 0 ||
		value.Revision > math.MaxInt64 || value.Revision == 1 && value.PreviousProvenanceDigest != "" ||
		value.Revision > 1 && !digestPattern.MatchString(value.PreviousProvenanceDigest) {
		return newError(Denied, "graph_invalid", false, nil)
	}
	tasks := make(map[string]Task, len(value.Tasks))
	active, roots := uint32(0), 0
	priorTask := ""
	for _, task := range value.Tasks {
		if task.TaskID <= priorTask || validateTask(task, value) != nil {
			return newError(Denied, "graph_task_invalid", false, nil)
		}
		priorTask = task.TaskID
		if _, exists := tasks[task.TaskID]; exists {
			return newError(Denied, "graph_task_duplicate", false, nil)
		}
		tasks[task.TaskID] = task
		if len(task.ParentTaskIDs) == 0 {
			roots++
		}
		if task.Status == TaskPending || task.Status == TaskDispatching {
			active++
		}
	}
	if roots != 1 || active > value.Limits.MaximumConcurrency {
		return newError(Denied, "graph_bounds_invalid", false, nil)
	}
	wantEdges := make(map[string]bool)
	fanout := make(map[string]uint32)
	for _, task := range value.Tasks {
		if len(task.ParentTaskIDs) == 0 {
			if task.Role != CoordinatorRole || task.Depth != 0 {
				return newError(Denied, "graph_root_invalid", false, nil)
			}
			continue
		}
		maximumDepth := uint32(0)
		for _, parentID := range task.ParentTaskIDs {
			parent, exists := tasks[parentID]
			if !exists || parent.Depth >= task.Depth || parent.Deadline.Before(task.Deadline) {
				return newError(Denied, "graph_parent_invalid", false, nil)
			}
			if parent.Depth > maximumDepth {
				maximumDepth = parent.Depth
			}
			fanout[parentID]++
			if fanout[parentID] > value.Limits.MaximumFanout {
				return newError(Denied, "graph_fanout_exhausted", false, nil)
			}
			wantEdges[parentID+"\x00"+task.TaskID] = true
		}
		if task.Depth != maximumDepth+1 || task.Depth > value.Limits.MaximumDepth {
			return newError(Denied, "graph_depth_invalid", false, nil)
		}
	}
	if err := validateEdges(value.Edges, wantEdges, tasks); err != nil {
		return err
	}
	if err := validateReceipts(value.Receipts, tasks, value.Cancellations, value.Revision); err != nil {
		return err
	}
	if err := validateCancellations(value.Cancellations, tasks, value); err != nil {
		return err
	}
	expected, err := graphProvenanceDigest(value)
	if err != nil || expected != value.ProvenanceDigest {
		return newError(Denied, "graph_provenance_invalid", false, err)
	}
	return nil
}

func validateTask(value Task, graph Graph) error {
	if !uuidPattern.MatchString(value.TaskID) || len(value.ParentTaskIDs) > MaximumParents ||
		!validUUIDSet(value.ParentTaskIDs) || !validRole(value.Role) || !validTaskStatus(value.Status) ||
		value.Depth > graph.Limits.MaximumDepth || !validDigestSet(value.InputRefs, true) ||
		!digestPattern.MatchString(value.AssignmentDigest) || !digestPattern.MatchString(value.BudgetReservationDigest) ||
		value.BudgetSettlementDigest != "" && !digestPattern.MatchString(value.BudgetSettlementDigest) ||
		!validTimes(value.CreatedAt, value.UpdatedAt) || value.CreatedAt.Before(graph.CreatedAt) ||
		!value.Deadline.After(value.CreatedAt) || value.Deadline.After(graph.Deadline) ||
		value.UpdatedAt.After(graph.Deadline) || value.Revision == 0 || value.Revision > math.MaxInt64 ||
		value.PreviousProvenanceDigest != "" && !digestPattern.MatchString(value.PreviousProvenanceDigest) {
		return newError(Denied, "task_invalid", false, nil)
	}
	assignment, err := assignmentBindingDigest(value)
	if err != nil || assignment != value.AssignmentDigest {
		return newError(Denied, "task_assignment_invalid", false, err)
	}
	switch value.Status {
	case TaskPending, TaskDispatching:
		if value.Result != nil || value.Cancellation != nil || value.BudgetSettlementDigest != "" {
			return newError(Denied, "task_state_invalid", false, nil)
		}
	case TaskSucceeded:
		if value.Result == nil || value.Cancellation != nil || validateStructuredResult(*value.Result) != nil || value.Result.TaskID != value.TaskID || value.Result.Role != value.Role {
			return newError(Denied, "task_result_invalid", false, nil)
		}
	case TaskCanceled:
		if value.Result != nil || validateCancellation(value.Cancellation, value.TaskID) != nil {
			return newError(Denied, "task_cancellation_invalid", false, nil)
		}
	case TaskUncertain:
		if value.Result != nil || value.Cancellation != nil && validateCancellation(value.Cancellation, value.TaskID) != nil {
			return newError(Denied, "task_uncertain_invalid", false, nil)
		}
	default:
		if value.Result != nil || value.Cancellation != nil {
			return newError(Denied, "task_terminal_invalid", false, nil)
		}
	}
	provenance, err := taskProvenanceDigest(value)
	if err != nil || provenance != value.ProvenanceDigest {
		return newError(Denied, "task_provenance_invalid", false, err)
	}
	return nil
}

func validateStructuredResult(value StructuredResult) error {
	copyValue := cloneStructuredResult(value)
	copyValue.ResultDigest = ""
	if err := validateStructuredResultShape(copyValue); err != nil {
		return err
	}
	digestValue, err := ResultBindingDigest(copyValue)
	if err != nil || digestValue != value.ResultDigest {
		return newError(Denied, "result_digest_invalid", false, err)
	}
	return nil
}

func validateStructuredResultShape(value StructuredResult) error {
	if !uuidPattern.MatchString(value.TaskID) || !validRole(value.Role) || !validArtifact(value.Artifact) ||
		len(value.Claims)+len(value.Findings) == 0 || len(value.Claims) > MaximumResults ||
		len(value.Findings) > MaximumResults || !validCompleteness(value.Completeness) ||
		!digestPattern.MatchString(value.RuntimeDigest) || value.ResultDigest != "" {
		return newError(Denied, "result_invalid", false, nil)
	}
	prior := ""
	for _, claim := range value.Claims {
		if claim.ClaimID <= prior || validateClaim(claim) != nil {
			return newError(Denied, "claim_invalid", false, nil)
		}
		prior = claim.ClaimID
	}
	prior = ""
	for _, finding := range value.Findings {
		if finding.FindingID <= prior || validateFinding(finding) != nil {
			return newError(Denied, "finding_invalid", false, nil)
		}
		prior = finding.FindingID
	}
	return nil
}

func validateClaim(value Claim) error {
	if !uuidPattern.MatchString(value.ClaimID) || !digestPattern.MatchString(value.StatementDigest) ||
		!validDigestSet(value.EvidenceRefs, false) || !validDigestSet(value.CounterevidenceRefs, true) ||
		value.ConfidenceBasisPoints > 10000 || !validDigestSet(value.UnknownDigests, true) ||
		!validDigestSet(value.RecommendedNextStepDigests, false) {
		return newError(Denied, "claim_invalid", false, nil)
	}
	return nil
}

func validateFinding(value Finding) error {
	if !uuidPattern.MatchString(value.FindingID) || !digestPattern.MatchString(value.SummaryDigest) ||
		!slices.Contains([]string{"observed", "suspected", "confirmed", "rejected"}, value.Status) ||
		!slices.Contains([]string{"informational", "low", "medium", "high", "critical"}, value.Severity) ||
		!validDigestSet(value.EvidenceRefs, false) || !validDigestSet(value.CounterevidenceRefs, true) ||
		value.ConfidenceBasisPoints > 10000 || !validDigestSet(value.UnknownDigests, true) ||
		!validDigestSet(value.RecommendedNextStepDigests, false) {
		return newError(Denied, "finding_invalid", false, nil)
	}
	return nil
}

func validateDecision(value Decision, request AuthorizationRequest, now time.Time) error {
	copyValue := value
	copyValue.DecisionDigest = ""
	expected, err := DecisionBindingDigest(copyValue)
	if err != nil || value.DecisionDigest != expected || value.IntentDigest != request.IntentDigest ||
		value.Operation != request.Operation || value.GraphID != request.GraphID || value.TaskID != request.TaskID ||
		value.Case != request.Case || value.ActorID != request.ActorID || value.ActorRevision != request.ActorRevision ||
		value.PolicyDigest != request.PolicyDigest || value.IssuedAt.After(now) || !value.ExpiresAt.After(now) ||
		value.ExpiresAt.After(request.Deadline) {
		return newError(Denied, "decision_invalid", false, err)
	}
	return nil
}

func validateDecisionShape(value Decision) error {
	if value.SchemaVersion != DecisionSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.DecisionID) || value.DecisionDigest != "" ||
		!digestPattern.MatchString(value.IntentDigest) || !validOperation(value.Operation) ||
		!uuidPattern.MatchString(value.GraphID) || !uuidPattern.MatchString(value.TaskID) || !validCase(value.Case) ||
		!uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 ||
		!digestPattern.MatchString(value.PolicyDigest) || !digestPattern.MatchString(value.RevocationDigest) ||
		(value.Outcome != "allow" && value.Outcome != "deny") || !tokenPattern.MatchString(value.ReasonCode) ||
		!validTimes(value.IssuedAt, value.ExpiresAt) || !value.ExpiresAt.After(value.IssuedAt) ||
		value.Revision == 0 || value.Revision > math.MaxInt64 {
		return newError(Denied, "decision_invalid", false, nil)
	}
	return nil
}

func validateEdges(edges []Edge, wanted map[string]bool, tasks map[string]Task) error {
	if len(edges) != len(wanted) {
		return newError(Denied, "graph_edges_invalid", false, nil)
	}
	prior := ""
	for _, edge := range edges {
		key := edge.ParentTaskID + "\x00" + edge.ChildTaskID
		if key <= prior || !wanted[key] || tasks[edge.ParentTaskID].Depth >= tasks[edge.ChildTaskID].Depth {
			return newError(Denied, "graph_edges_invalid", false, nil)
		}
		prior = key
	}
	return nil
}

func validateReceipts(values []Receipt, tasks map[string]Task, cancellations []CancellationRecord, graphRevision uint64) error {
	prior := ""
	creationReceipts := map[string]int{}
	for _, receipt := range values {
		if receipt.IdempotencyDigest <= prior || !validOperation(receipt.Operation) ||
			!digestPattern.MatchString(receipt.IdempotencyDigest) || !digestPattern.MatchString(receipt.IntentDigest) ||
			!uuidPattern.MatchString(receipt.TaskID) || receipt.Revision == 0 || receipt.Revision > graphRevision ||
			receipt.Revision > math.MaxInt64 {
			return newError(Denied, "graph_receipts_invalid", false, nil)
		}
		task, exists := tasks[receipt.TaskID]
		if !exists {
			return newError(Denied, "graph_receipt_task_missing", false, nil)
		}
		switch receipt.Operation {
		case CreateGraph:
			if len(task.ParentTaskIDs) != 0 {
				return newError(Denied, "graph_create_receipt_invalid", false, nil)
			}
			creationReceipts[task.TaskID]++
		case Delegate:
			if len(task.ParentTaskIDs) == 0 {
				return newError(Denied, "graph_delegate_receipt_invalid", false, nil)
			}
			creationReceipts[task.TaskID]++
		case Execute:
			if !terminalTask(task.Status) || task.Status == TaskCanceled {
				return newError(Denied, "graph_execute_receipt_invalid", false, nil)
			}
		case Cancel:
			found := false
			for _, cancellation := range cancellations {
				if cancellation.IdempotencyDigest == receipt.IdempotencyDigest &&
					cancellation.IntentDigest == receipt.IntentDigest && cancellation.RootTaskID == receipt.TaskID &&
					cancellation.Status != CancellationActive {
					found = true
				}
			}
			if !found {
				return newError(Denied, "graph_cancel_receipt_invalid", false, nil)
			}
		}
		prior = receipt.IdempotencyDigest
	}
	for taskID := range tasks {
		if creationReceipts[taskID] != 1 {
			return newError(Denied, "graph_creation_receipt_invalid", false, nil)
		}
	}
	return nil
}

func validateCancellation(value *CancellationAck, taskID string) error {
	if value == nil || value.TaskID != taskID ||
		!slices.Contains([]string{"canceled", "already_terminal", "uncertain"}, value.Outcome) ||
		!digestPattern.MatchString(value.EvidenceDigest) || !digestPattern.MatchString(value.ProvenanceDigest) {
		return newError(Denied, "cancellation_invalid", false, nil)
	}
	return nil
}

func validateCancellations(values []CancellationRecord, tasks map[string]Task, graph Graph) error {
	if len(values) > MaximumTasks {
		return newError(Denied, "cancellations_invalid", false, nil)
	}
	prior := ""
	idempotencies := map[string]bool{}
	boundTaskAcks := map[string]CancellationAck{}
	for _, value := range values {
		if value.CancellationID <= prior || !uuidPattern.MatchString(value.CancellationID) ||
			!uuidPattern.MatchString(value.RootTaskID) || !digestPattern.MatchString(value.ReasonDigest) ||
			len(value.TargetTaskIDs) == 0 || len(value.TargetTaskIDs) > MaximumTasks ||
			len(value.Acknowledgments) > len(value.TargetTaskIDs) ||
			!digestPattern.MatchString(value.IntentDigest) || !digestPattern.MatchString(value.IdempotencyDigest) ||
			!validTimes(value.CreatedAt, value.UpdatedAt) || value.CreatedAt.Before(graph.CreatedAt) ||
			value.UpdatedAt.After(graph.Deadline) || value.Revision == 0 || value.Revision > math.MaxInt64 {
			return newError(Denied, "cancellation_invalid", false, nil)
		}
		if _, exists := tasks[value.RootTaskID]; !exists {
			return newError(Denied, "cancellation_root_missing", false, nil)
		}
		if idempotencies[value.IdempotencyDigest] {
			return newError(Denied, "cancellation_idempotency_duplicate", false, nil)
		}
		idempotencies[value.IdempotencyDigest] = true
		if expected := cancellationTargets(graph, value.RootTaskID); !slices.Equal(expected, value.TargetTaskIDs) {
			return newError(Denied, "cancellation_targets_incomplete", false, nil)
		}
		seen := map[string]bool{}
		for index, taskID := range value.TargetTaskIDs {
			if !uuidPattern.MatchString(taskID) || seen[taskID] {
				return newError(Denied, "cancellation_targets_invalid", false, nil)
			}
			if _, exists := tasks[taskID]; !exists {
				return newError(Denied, "cancellation_target_missing", false, nil)
			}
			seen[taskID] = true
			if index < len(value.Acknowledgments) {
				ack := value.Acknowledgments[index]
				if validateCancellation(&ack, taskID) != nil {
					return newError(Denied, "cancellation_ack_invalid", false, nil)
				}
				task := tasks[taskID]
				switch ack.Outcome {
				case "canceled":
					if task.Status != TaskCanceled || task.Cancellation == nil || *task.Cancellation != ack {
						return newError(Denied, "cancellation_task_binding_invalid", false, nil)
					}
					boundTaskAcks[taskID] = ack
				case "uncertain":
					if task.Status != TaskUncertain || task.Cancellation == nil || *task.Cancellation != ack {
						return newError(Denied, "cancellation_task_binding_invalid", false, nil)
					}
					boundTaskAcks[taskID] = ack
				case "already_terminal":
					if !terminalTask(task.Status) {
						return newError(Denied, "cancellation_terminal_binding_invalid", false, nil)
					}
				}
			}
		}
		switch value.Status {
		case CancellationActive:
			if len(value.Acknowledgments) == len(value.TargetTaskIDs) {
				return newError(Denied, "cancellation_active_invalid", false, nil)
			}
		case CancellationCompleted:
			if len(value.Acknowledgments) != len(value.TargetTaskIDs) {
				return newError(Denied, "cancellation_incomplete", false, nil)
			}
			for _, ack := range value.Acknowledgments {
				if ack.Outcome == "uncertain" {
					return newError(Denied, "cancellation_outcome_invalid", false, nil)
				}
			}
		case CancellationUncertain:
			if len(value.Acknowledgments) != len(value.TargetTaskIDs) {
				return newError(Denied, "cancellation_uncertain_incomplete", false, nil)
			}
			found := false
			for _, ack := range value.Acknowledgments {
				found = found || ack.Outcome == "uncertain"
			}
			if !found {
				return newError(Denied, "cancellation_uncertain_missing", false, nil)
			}
		default:
			return newError(Denied, "cancellation_status_invalid", false, nil)
		}
		prior = value.CancellationID
	}
	for taskID, task := range tasks {
		if task.Cancellation == nil {
			continue
		}
		if ack, found := boundTaskAcks[taskID]; !found || ack != *task.Cancellation {
			return newError(Denied, "task_cancellation_orphaned", false, nil)
		}
	}
	return nil
}

func validateLimits(value Limits) error {
	if value.MaximumDepth == 0 || value.MaximumDepth > 32 || value.MaximumFanout == 0 || value.MaximumFanout > 64 ||
		value.MaximumConcurrency == 0 || value.MaximumConcurrency > 64 || value.MaximumTasks == 0 || value.MaximumTasks > MaximumTasks {
		return newError(InvalidInput, "limits_invalid", false, nil)
	}
	return nil
}

func validRole(value Role) bool {
	switch value {
	case CoordinatorRole, AlertTriageRole, SIEMQueryRole, TimelineCorrelationRole, HuntingRole,
		CTIAttackRole, DetectionRole, VulnerabilityRole, ValidationRole, IRPlannerRole, ReviewerRole, ReportWriterRole:
		return true
	default:
		return false
	}
}
func validOperation(value Operation) bool {
	return slices.Contains([]Operation{CreateGraph, Delegate, Execute, Cancel, Recover}, value)
}
func validTaskStatus(value TaskStatus) bool {
	return slices.Contains([]TaskStatus{TaskPending, TaskDispatching, TaskSucceeded, TaskFailed, TaskDenied, TaskCanceled, TaskTimedOut, TaskUncertain}, value)
}
func validCompleteness(value Completeness) bool {
	return slices.Contains([]Completeness{Complete, Partial, Empty, Uncertain}, value)
}
func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID)
}
func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && value.MediaType == "application/json" &&
		tokenPattern.MatchString(value.Classification) && value.Length > 0 && value.Length <= 1<<30
}
func validDigestSet(values []string, empty bool) bool {
	if (!empty && len(values) == 0) || len(values) > MaximumReferences || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !digestPattern.MatchString(value) || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}
func validUUIDSet(values []string) bool {
	if !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !uuidPattern.MatchString(value) || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}
func validTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }
func validTimes(first, second time.Time) bool {
	return validTime(first) && validTime(second) && !second.Before(first)
}
func validOpaque(value string) bool {
	return len(value) > 0 && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", false, nil)
	}
	if ctx.Err() == context.Canceled {
		return newError(Canceled, "request_canceled", false, context.Canceled)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return newError(Timeout, "request_timeout", false, context.DeadlineExceeded)
	}
	return nil
}
