package estop

import (
	"context"
	"regexp"
	"sort"
	"sync"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

var controlIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

func New(store Store, audit AuditSink, controls ...Control) (*Controller, error) {
	return NewWithDependencies(store, audit, systemClock{}, controls...)
}

func NewWithDependencies(store Store, audit AuditSink, clock Clock, controls ...Control) (*Controller, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, brokerError(stopcontract.InvalidInput, "controller_configuration_invalid")
	}
	required := map[string]bool{"credential": false, "egress": false, "remote_job": false, "workflow": false, "cooperative": false}
	identities := make(map[string]bool)
	cloned := append([]Control(nil), controls...)
	for _, control := range cloned {
		if control == nil || !controlIDPattern.MatchString(control.ID()) || identities[control.ID()] {
			return nil, brokerError(stopcontract.InvalidInput, "control_configuration_invalid")
		}
		if _, ok := stopcontract.ControlObjective(control.Kind()); !ok || control.Kind() == "lease" {
			return nil, brokerError(stopcontract.InvalidInput, "control_configuration_invalid")
		}
		identities[control.ID()] = true
		if _, exists := required[control.Kind()]; exists {
			required[control.Kind()] = true
		}
	}
	for _, present := range required {
		if !present {
			return nil, brokerError(stopcontract.InvalidInput, "required_control_missing")
		}
	}
	sort.Slice(cloned, func(i, j int) bool { return cloned[i].ID() < cloned[j].ID() })
	return &Controller{store: store, audit: audit, clock: clock, controls: cloned}, nil
}

func (controller *Controller) Activate(ctx context.Context, command stopcontract.Command, authority stopcontract.Authority) (stopcontract.Result, stopcontract.Decision, error) {
	now := time.Time{}
	if controller != nil && controller.clock != nil {
		now = controller.clock.Now().UTC()
	}
	if controller == nil || controller.store == nil || controller.audit == nil || controller.clock == nil {
		err := brokerError(stopcontract.Unavailable, "controller_unavailable")
		return stopcontract.Result{}, activationDecision(command, authority, stopcontract.State{}, err, now), err
	}
	if err := normalizeContext(ctx); err != nil {
		return controller.recordDenied(ctx, command, authority, err, now)
	}
	if err := stopcontract.ValidateCommand(command); err != nil {
		return controller.recordDenied(ctx, command, authority, err, now)
	}
	if err := validateAuthority(command, authority, now); err != nil {
		return controller.recordDenied(ctx, command, authority, err, now)
	}
	digest, _ := stopcontract.CommandDigest(command)
	record, created, err := controller.store.Activate(ctx, ActivationCandidate{
		Command: command, Authority: authority, RequestDigest: digest, ActivatedAt: now,
	})
	if err != nil {
		return controller.recordDenied(ctx, command, authority, normalizeStoreError(ctx, err), now)
	}
	if created == ActivationConflict {
		err = brokerError(stopcontract.Conflict, "activation_conflict")
		return controller.recordDenied(ctx, command, authority, err, now)
	}
	if created == ActivationReplay {
		return stopcontract.Result{State: record.State}, record.Decision, nil
	}
	auditPending := controller.deliverAudit(ctx, stopcontract.AuditRecord{ID: record.AuditID, Decision: record.Decision}) != nil
	acks, controlPending, controlErr := controller.applyControls(ctx, record.State)
	result := stopcontract.Result{State: record.State, Acknowledgements: acks, AuditPending: auditPending || controlPending}
	if controlErr != nil {
		return result, record.Decision, controlErr
	}
	if result.AuditPending {
		return result, record.Decision, brokerError(stopcontract.Unavailable, "audit_delivery_pending")
	}
	return result, record.Decision, nil
}

func validateAuthority(command stopcontract.Command, authority stopcontract.Authority, now time.Time) error {
	if err := stopcontract.ValidateAuthority(authority, now); err != nil {
		return err
	}
	if command.Scope != authority.Scope || command.ActorID != authority.ActorID {
		return brokerError(stopcontract.Denied, "authority_scope_mismatch")
	}
	return nil
}

func (controller *Controller) recordDenied(ctx context.Context, command stopcontract.Command, authority stopcontract.Authority, resultErr error, now time.Time) (stopcontract.Result, stopcontract.Decision, error) {
	decision := activationDecision(command, authority, stopcontract.State{}, resultErr, now)
	record, err := controller.store.ReserveAudit(context.WithoutCancel(nonNilContext(ctx)), decision)
	if err != nil {
		storeErr := normalizeStoreError(nonNilContext(ctx), err)
		return stopcontract.Result{}, activationDecision(command, authority, stopcontract.State{}, storeErr, now), storeErr
	}
	if err := controller.deliverAudit(ctx, record); err != nil {
		return stopcontract.Result{AuditPending: true}, decision, brokerError(stopcontract.Unavailable, "audit_delivery_pending")
	}
	return stopcontract.Result{}, decision, resultErr
}

func activationDecision(command stopcontract.Command, authority stopcontract.Authority, state stopcontract.State, err error, now time.Time) stopcontract.Decision {
	result, reason := outcome(err, "stop_activated")
	decision := stopcontract.Decision{Event: "activation", Outcome: result, ReasonCode: reason,
		RequestID: command.RequestID, Scope: command.Scope, Epoch: state.Epoch, ActorID: command.ActorID,
		ActorRevision: authority.ActorRevision, AuthorizationDecisionDigest: authority.AuthorizationDecisionDigest,
		PolicyDecisionDigest: authority.PolicyDecisionDigest, ActivatedAt: state.ActivatedAt, OccurredAt: now}
	if stopcontract.Code(err) == stopcontract.InvalidInput {
		decision.ActorID, decision.AuthorizationDecisionDigest, decision.PolicyDecisionDigest = "", "", ""
	}
	return stopcontract.FinalizeDecision(decision)
}

func (controller *Controller) applyControls(ctx context.Context, state stopcontract.State) ([]stopcontract.Acknowledgement, bool, error) {
	base := context.WithoutCancel(nonNilContext(ctx))
	acks := make([]stopcontract.Acknowledgement, len(controller.controls))
	pending := make([]bool, len(controller.controls))
	errorsByIndex := make([]error, len(controller.controls))
	var wait sync.WaitGroup
	wait.Add(len(controller.controls))
	for index, control := range controller.controls {
		go func(index int, control Control) {
			defer wait.Done()
			ack, auditPending, err := controller.applyControl(base, state, control)
			acks[index], pending[index], errorsByIndex[index] = ack, auditPending, err
		}(index, control)
	}
	wait.Wait()
	sort.Slice(acks, func(i, j int) bool { return acks[i].ControlID < acks[j].ControlID })
	anyPending, anyFailure := false, false
	for index := range pending {
		anyPending = anyPending || pending[index]
		anyFailure = anyFailure || errorsByIndex[index] != nil
	}
	if anyFailure {
		return acks, anyPending, brokerError(stopcontract.Unavailable, "containment_incomplete")
	}
	return acks, anyPending, nil
}

func (controller *Controller) applyControl(base context.Context, state stopcontract.State, control Control) (stopcontract.Acknowledgement, bool, error) {
	objective, _ := stopcontract.ControlObjective(control.Kind())
	startedWall := controller.clock.Now().UTC()
	startedMonotonic := time.Now()
	controlCtx, cancel := context.WithTimeout(base, objective)
	evidenceDigest, applyErr := control.Apply(controlCtx, stopcontract.ControlRequest{
		Scope: state.Scope, Epoch: state.Epoch, ActivatedAt: state.ActivatedAt,
	})
	cancel()
	elapsed := time.Since(startedMonotonic)
	completed := controller.clock.Now().UTC()
	outcomeValue, reason := "applied", "control_applied"
	if elapsed > objective {
		outcomeValue, reason = "timeout", "control_timeout"
		evidenceDigest = ""
	} else if applyErr != nil {
		outcomeValue, reason = controlError(applyErr, controlCtx)
		evidenceDigest = ""
	}
	ack := stopcontract.Acknowledgement{SchemaVersion: stopcontract.AckSchemaVersion,
		ContractVersion: stopcontract.ContractVersion, Scope: state.Scope, Epoch: state.Epoch,
		ControlID: control.ID(), ControlKind: control.Kind(), Outcome: outcomeValue, ReasonCode: reason,
		EvidenceDigest: evidenceDigest, StartedAt: startedWall, CompletedAt: completed,
		ElapsedNanos: elapsed.Nanoseconds(), ObjectiveNanos: objective.Nanoseconds()}
	if err := stopcontract.ValidateAcknowledgement(ack); err != nil {
		ack.Outcome, ack.ReasonCode, ack.EvidenceDigest = "failed", "control_evidence_invalid", ""
		applyErr = err
	}
	decision := controlDecision(state, ack)
	audit, result, err := controller.store.RecordControl(base, state, ack, decision)
	if err != nil || result == ControlConflict {
		return ack, false, brokerError(stopcontract.Unavailable, "control_record_unavailable")
	}
	auditPending := false
	if result == ControlNew {
		auditPending = controller.deliverAudit(base, audit) != nil
	}
	if ack.Outcome != "applied" || applyErr != nil {
		return ack, auditPending, brokerError(stopcontract.Unavailable, ack.ReasonCode)
	}
	return ack, auditPending, nil
}

func controlDecision(state stopcontract.State, ack stopcontract.Acknowledgement) stopcontract.Decision {
	outcomeValue := "allowed"
	if ack.Outcome != "applied" {
		outcomeValue = "unavailable"
	}
	return stopcontract.FinalizeDecision(stopcontract.Decision{Event: "control_ack", Outcome: outcomeValue,
		ReasonCode: ack.ReasonCode, RequestID: state.RequestID, Scope: state.Scope, Epoch: state.Epoch,
		ActorID: state.ActorID, ActorRevision: state.ActorRevision, ControlID: ack.ControlID,
		ControlKind: ack.ControlKind, ControlOutcome: ack.Outcome, EvidenceDigest: ack.EvidenceDigest,
		AuthorizationDecisionDigest: state.AuthorizationDecisionDigest, PolicyDecisionDigest: state.PolicyDecisionDigest,
		ActivatedAt: state.ActivatedAt, OccurredAt: ack.CompletedAt, ElapsedNanos: ack.ElapsedNanos,
		ObjectiveNanos: ack.ObjectiveNanos})
}

func (controller *Controller) deliverAudit(ctx context.Context, record stopcontract.AuditRecord) error {
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := controller.audit.AppendEmergencyStopDecision(auditCtx, record.Decision); err != nil {
		return err
	}
	if err := controller.store.MarkAuditDelivered(auditCtx, record.ID); err != nil {
		return err
	}
	return nil
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
