// Package localauth authenticates named local actors and issues short-lived,
// revocable sessions at the API and CLI transport boundary.
package localauth

import (
	"context"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

const (
	SchemaVersion   = "coh.local-auth/v1"
	ContractVersion = "1.0.0"
)

type Clock interface {
	Now() time.Time
}

type ActorDirectory interface {
	LookupActor(context.Context, string, string) (localidentity.Actor, error)
}

type ChallengeStore interface {
	SaveChallenge(context.Context, ChallengeRecord) error
	TakeChallenge(context.Context, string) (ChallengeRecord, error)
}

type SessionStore interface {
	SaveSession(context.Context, SessionRecord) error
	LookupSession(context.Context, string) (SessionRecord, error)
	RevokeSession(context.Context, string, time.Time) error
}

type AuditSink interface {
	AppendAuthenticationEvent(context.Context, AuthenticationEvent) error
}

type Service struct {
	Actors       ActorDirectory
	Challenges   ChallengeStore
	Sessions     SessionStore
	Audit        AuditSink
	Random       io.Reader
	Clock        Clock
	ChallengeTTL time.Duration
	SessionTTL   time.Duration
}

type BeginRequest struct {
	OrganizationID string
	ActorID        string
}

type Challenge struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	ID              string    `json:"id"`
	OrganizationID  string    `json:"organization_id"`
	ActorID         string    `json:"actor_id"`
	SigningMessage  string    `json:"signing_message"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type ChallengeRecord struct {
	ID             string
	OrganizationID string
	ActorID        string
	ActorRevision  uint64
	PublicKey      string
	Message        []byte
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

type CompleteRequest struct {
	ChallengeID string
	Signature   string
}

type IssuedSession struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	ID              string    `json:"id"`
	Token           string    `json:"token"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type SessionRecord struct {
	ID             string
	TokenDigest    string
	OrganizationID string
	ActorID        string
	ActorRevision  uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	RevokedAt      time.Time
}

// AuthenticationEvent is safe audit input. It excludes public keys,
// signatures, signing messages, session tokens, token digests, and backend
// error details.
type AuthenticationEvent struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	EventDigest     string    `json:"event_digest"`
	Outcome         string    `json:"outcome"`
	ReasonCode      string    `json:"reason_code"`
	OrganizationID  string    `json:"organization_id,omitempty"`
	ActorID         string    `json:"actor_id,omitempty"`
	ActorRevision   uint64    `json:"actor_revision,omitempty"`
	ChallengeID     string    `json:"challenge_id,omitempty"`
	SessionID       string    `json:"session_id,omitempty"`
	OccurredAt      time.Time `json:"occurred_at"`
}
