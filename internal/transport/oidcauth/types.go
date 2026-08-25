// Package oidcauth implements the pinned server/Compose OIDC login boundary
// and current-actor RBAC checks for every authenticated request.
package oidcauth

import (
	"context"
	"crypto"
	"io"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
	"github.com/ArronJablonowski/COH/internal/domain/oidcidentity"
)

const (
	SchemaVersion   = "coh.server-oidc-auth/v1"
	ContractVersion = "1.0.0"
)

type Clock interface{ Now() time.Time }

type ActorDirectory interface {
	LookupOIDCActor(context.Context, string, string) (localidentity.Actor, error)
	LookupActor(context.Context, string, string) (localidentity.Actor, error)
}

type StateStore interface {
	SaveLoginState(context.Context, LoginStateRecord) error
	TakeLoginState(context.Context, string) (LoginStateRecord, error)
}

type SessionStore interface {
	SaveSession(context.Context, SessionRecord) error
	LookupSession(context.Context, string) (SessionRecord, error)
	RevokeSession(context.Context, string, time.Time) error
}

type ReplayStore interface {
	CheckAndStore(context.Context, ReplayRecord) (ReplayResult, error)
}

type KeySource interface {
	LookupKey(context.Context, string, string, string) (KeyRecord, error)
}

type AuditSink interface {
	AppendOIDCEvent(context.Context, Event) error
	AppendAuthorizationDecision(context.Context, localidentity.Decision) error
}

type Service struct {
	Config     oidcidentity.ProviderConfig
	Actors     ActorDirectory
	States     StateStore
	Sessions   SessionStore
	Replay     ReplayStore
	Keys       KeySource
	Audit      AuditSink
	Random     io.Reader
	Clock      Clock
	StateTTL   time.Duration
	SessionTTL time.Duration
}

type KeyRecord struct {
	Issuer          string
	SourceReference string
	ID              string
	Algorithm       string
	Revision        uint64
	Active          bool
	PublicKey       crypto.PublicKey
	NotBefore       time.Time
	ExpiresAt       time.Time
}

type BeginRequest struct {
	OrganizationID string
	Audience       string
}

type LoginState struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	ID              string    `json:"id"`
	Issuer          string    `json:"issuer"`
	Audience        string    `json:"audience"`
	Nonce           string    `json:"nonce"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type LoginStateRecord struct {
	ID                    string
	OrganizationID        string
	Issuer                string
	Audience              string
	NonceDigest           string
	ProfileKind           string
	ProfileDecisionDigest string
	CreatedAt             time.Time
	ExpiresAt             time.Time
}

type SessionRecord struct {
	ID                    string
	TokenDigest           string
	OrganizationID        string
	ActorID               string
	ActorRevision         uint64
	IssuerDigest          string
	SubjectDigest         string
	KeyID                 string
	Algorithm             string
	KeyRevision           uint64
	ProfileKind           string
	ProfileDecisionDigest string
	IssuedAt              time.Time
	ExpiresAt             time.Time
	RevokedAt             time.Time
}

type IssuedSession struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
	mu        sync.Mutex
	token     []byte
	destroyed bool
}

func (session *IssuedSession) UseToken(consumer func(string) error) error {
	if session == nil || consumer == nil {
		return authError(localidentity.Denied, "session_destroyed")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.destroyed || len(session.token) == 0 {
		return authError(localidentity.Denied, "session_destroyed")
	}
	copyOfToken := append([]byte(nil), session.token...)
	defer zero(copyOfToken)
	return consumer(string(copyOfToken))
}

func (session *IssuedSession) Destroy() {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.destroyed {
		zero(session.token)
		session.token = nil
		session.destroyed = true
	}
}

type ReplayResult string

const (
	ReplayNew      ReplayResult = "new"
	ReplayExact    ReplayResult = "exact_replay"
	ReplayConflict ReplayResult = "conflict"
)

type ReplayRecord struct {
	SessionID      string
	IdempotencyKey string
	RequestDigest  string
}

type Event struct {
	SchemaVersion         string    `json:"schema_version"`
	ContractVersion       string    `json:"contract_version"`
	EventDigest           string    `json:"event_digest"`
	Event                 string    `json:"event"`
	Outcome               string    `json:"outcome"`
	ReasonCode            string    `json:"reason_code"`
	ProfileKind           string    `json:"profile_kind,omitempty"`
	ProfileDecisionDigest string    `json:"profile_decision_digest,omitempty"`
	OrganizationID        string    `json:"organization_id,omitempty"`
	ActorID               string    `json:"actor_id,omitempty"`
	ActorRevision         uint64    `json:"actor_revision,omitempty"`
	IssuerDigest          string    `json:"issuer_digest,omitempty"`
	SubjectDigest         string    `json:"subject_digest,omitempty"`
	KeyIDDigest           string    `json:"key_id_digest,omitempty"`
	KeyRevision           uint64    `json:"key_revision,omitempty"`
	Algorithm             string    `json:"algorithm,omitempty"`
	StateID               string    `json:"state_id,omitempty"`
	SessionID             string    `json:"session_id,omitempty"`
	OccurredAt            time.Time `json:"occurred_at"`
}
