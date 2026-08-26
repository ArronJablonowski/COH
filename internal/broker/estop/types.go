// Package estop owns atomic emergency-stop activation, durable audit outbox
// reservation, effective-state checks, and bounded independent containment.
package estop

import (
	"context"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

type Clock interface{ Now() time.Time }

type AuditSink interface {
	AppendEmergencyStopDecision(context.Context, stopcontract.Decision) error
}

type Control interface {
	ID() string
	Kind() string
	Apply(context.Context, stopcontract.ControlRequest) (string, error)
}

type ActivationCandidate struct {
	Command       stopcontract.Command
	Authority     stopcontract.Authority
	RequestDigest string
	ActivatedAt   time.Time
}

type ActivationRecord struct {
	State    stopcontract.State
	Decision stopcontract.Decision
	AuditID  string
}

type ActivationResult string

const (
	ActivationNew      ActivationResult = "new"
	ActivationReplay   ActivationResult = "replay"
	ActivationConflict ActivationResult = "conflict"
)

type ControlRecordResult string

const (
	ControlNew      ControlRecordResult = "new"
	ControlReplay   ControlRecordResult = "replay"
	ControlConflict ControlRecordResult = "conflict"
)

type Store interface {
	Activate(context.Context, ActivationCandidate) (ActivationRecord, ActivationResult, error)
	Effective(context.Context, string, string, string) (stopcontract.State, bool, error)
	ReserveAudit(context.Context, stopcontract.Decision) (stopcontract.AuditRecord, error)
	RecordControl(context.Context, stopcontract.State, stopcontract.Acknowledgement, stopcontract.Decision) (stopcontract.AuditRecord, ControlRecordResult, error)
	PendingAudits(context.Context, int) ([]stopcontract.AuditRecord, error)
	MarkAuditDelivered(context.Context, string) error
}

type Controller struct {
	store    Store
	audit    AuditSink
	clock    Clock
	controls []Control
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }
