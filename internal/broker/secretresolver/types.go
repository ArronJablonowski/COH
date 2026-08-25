// Package secretresolver owns broker-only secret resolution. Raw values never
// cross into domain, workflow, provider, connector, transport, or evidence
// types.
package secretresolver

import (
	"context"
	"sync"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

const maximumSecretBytes = 64 * 1024

type Backend interface {
	Name() string
	Fetch(context.Context, secretref.Reference) (Record, error)
}

type Record struct {
	Backend         string
	EntryID         string
	Version         uint64
	Revision        uint64
	Active          bool
	OrganizationID  string
	TenantID        string
	AllCases        bool
	CaseIDs         []string
	CredentialClass string
	Value           []byte
}

type AuditSink interface {
	AppendSecretDecision(context.Context, secretref.Decision) error
}

type ReplayStore interface {
	CheckAndStore(context.Context, ReplayRecord) (ReplayResult, error)
}

type ReplayRecord struct {
	OrganizationID string
	ActorID        string
	IdempotencyKey string
	RequestDigest  string
}

type ReplayResult string

const (
	ReplayNew      ReplayResult = "new"
	ReplayExact    ReplayResult = "exact_replay"
	ReplayConflict ReplayResult = "conflict"
)

type Resolver struct {
	backends map[string]Backend
	audit    AuditSink
	replay   ReplayStore
}

// Secret owns a resolved byte slice. Use holds exclusive access while the
// broker consumes it. Destroy is idempotent and overwrites the owned bytes.
type Secret struct {
	mu        sync.Mutex
	value     []byte
	destroyed bool
}

func (secret *Secret) Use(consumer func([]byte) error) error {
	secret.mu.Lock()
	defer secret.mu.Unlock()
	if secret.destroyed || consumer == nil {
		return &secretref.Error{Code: secretref.Denied, Reason: "secret_destroyed"}
	}
	temporary := append([]byte(nil), secret.value...)
	defer zero(temporary)
	return consumer(temporary)
}

func (secret *Secret) Destroy() {
	secret.mu.Lock()
	defer secret.mu.Unlock()
	if secret.destroyed {
		return
	}
	zero(secret.value)
	secret.value = nil
	secret.destroyed = true
}

func newSecret(value []byte) *Secret {
	owned := append([]byte(nil), value...)
	zero(value)
	return &Secret{value: owned}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
