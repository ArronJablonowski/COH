// Package remoteworker owns remote-worker enrollment and short-lived runner
// capabilities. Capability bytes never cross a serializable contract.
package remoteworker

import (
	"context"
	"io"
	"sync"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

const tokenBytes = 32

type Clock interface{ Now() time.Time }

type AuditSink interface {
	AppendRemoteWorkerDecision(context.Context, workercontract.Decision) error
}

type EnrollmentResult string

const (
	EnrollmentNew      EnrollmentResult = "new"
	EnrollmentReplay   EnrollmentResult = "replay"
	EnrollmentConflict EnrollmentResult = "conflict"
)

type LeaseCreateResult string

const (
	LeaseNew      LeaseCreateResult = "new"
	LeaseReplay   LeaseCreateResult = "replay"
	LeaseConflict LeaseCreateResult = "conflict"
)

type EnrollmentStore interface {
	Enroll(context.Context, workercontract.WorkerRecord, string, string, uint64) (workercontract.WorkerRecord, EnrollmentResult, error)
	CurrentWorker(context.Context, workercontract.Scope, string) (workercontract.WorkerRecord, error)
	RevokeWorker(context.Context, workercontract.Scope, string, string, time.Time) (workercontract.WorkerRecord, error)
}

type LeaseRecord struct {
	LeaseID       string
	tokenDigest   [32]byte
	RequestDigest string
	Request       workercontract.LeaseRequest
	Authority     workercontract.LeaseAuthority
	IssuedAt      time.Time
	ExpiresAt     time.Time
	Revoked       bool
	RevokeReason  string
	Consumed      bool
}

type LeaseStore interface {
	CreateLease(context.Context, LeaseRecord) (LeaseCreateResult, error)
	ClaimLease(context.Context, string, [32]byte, time.Time) (LeaseRecord, error)
	RevokeLease(context.Context, string, string) (LeaseRecord, error)
	RevokeWorkerLeases(context.Context, workercontract.Scope, string, string) error
}

type Store interface {
	EnrollmentStore
	LeaseStore
}

type Broker struct {
	store  Store
	audit  AuditSink
	clock  Clock
	random io.Reader
	maxTTL time.Duration
}

type Handle struct {
	LeaseID string
	mu      sync.Mutex
	token   []byte
	dead    bool
}

func (handle *Handle) Destroy() {
	if handle == nil {
		return
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.dead {
		return
	}
	zero(handle.token)
	handle.token = nil
	handle.dead = true
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
