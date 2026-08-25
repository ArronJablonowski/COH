// Package credentiallease owns credential capability issuance and dispatch.
// Capability bytes never leave this package in serializable form.
package credentiallease

import (
	"context"
	"io"
	"sync"
	"time"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
)

const tokenBytes = 32

type Clock interface {
	Now() time.Time
}

type AuditSink interface {
	AppendCredentialLeaseDecision(context.Context, leasecontract.Decision) error
}

type Store interface {
	Create(context.Context, Record) (CreateResult, error)
	Revoke(context.Context, string, string) error
}

type CreateResult string

const (
	CreateNew      CreateResult = "new"
	CreateReplay   CreateResult = "replay"
	CreateConflict CreateResult = "conflict"
)

type Record struct {
	LeaseID       string
	TokenDigest   [32]byte
	RequestDigest string
	Request       leasecontract.IssuanceRequest
	Authority     leasecontract.IssuanceAuthority
	IssuedAt      time.Time
	ExpiresAt     time.Time
	Revoked       bool
	RevokeReason  string
	Consumed      bool
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
