package localauth

import (
	"context"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

// MemoryRepository provides atomic ephemeral challenge, session, and replay
// state for the native workstation profile. Audit is intentionally not part of
// this repository because authorization requires a durable AuditSink.
type MemoryRepository struct {
	mu         sync.RWMutex
	actors     map[string]localidentity.Actor
	challenges map[string]ChallengeRecord
	sessions   map[string]SessionRecord
	sessionIDs map[string]string
	replay     map[string]ReplayRecord
}

func NewMemoryRepository(actors []localidentity.Actor) (*MemoryRepository, error) {
	repository := &MemoryRepository{
		actors: make(map[string]localidentity.Actor, len(actors)), challenges: make(map[string]ChallengeRecord),
		sessions: make(map[string]SessionRecord), sessionIDs: make(map[string]string), replay: make(map[string]ReplayRecord),
	}
	for _, actor := range actors {
		if err := localidentity.ValidateActor(actor); err != nil {
			return nil, authError(localidentity.InvalidInput, "actor_invalid")
		}
		key := actorKey(actor.OrganizationID, actor.ID)
		if _, exists := repository.actors[key]; exists {
			return nil, authError(localidentity.Conflict, "actor_conflict")
		}
		repository.actors[key] = cloneActor(actor)
	}
	return repository, nil
}

func (repository *MemoryRepository) LookupActor(ctx context.Context, organizationID, actorID string) (localidentity.Actor, error) {
	if err := ctx.Err(); err != nil {
		return localidentity.Actor{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	actor, exists := repository.actors[actorKey(organizationID, actorID)]
	if !exists {
		return localidentity.Actor{}, ErrNotFound
	}
	return cloneActor(actor), nil
}

// ReplaceActor applies an exact next revision. Role, grant, key, and active
// changes therefore invalidate all sessions bound to the previous revision.
func (repository *MemoryRepository) ReplaceActor(ctx context.Context, actor localidentity.Actor) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := localidentity.ValidateActor(actor); err != nil {
		return authError(localidentity.InvalidInput, "actor_invalid")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := actorKey(actor.OrganizationID, actor.ID)
	current, exists := repository.actors[key]
	if !exists {
		if actor.Revision != 1 {
			return authError(localidentity.Conflict, "actor_revision_conflict")
		}
	} else if actor.Revision != current.Revision+1 {
		return authError(localidentity.Conflict, "actor_revision_conflict")
	}
	repository.actors[key] = cloneActor(actor)
	return nil
}

func (repository *MemoryRepository) SaveChallenge(ctx context.Context, record ChallengeRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.challenges[record.ID]; exists {
		return ErrConflict
	}
	repository.challenges[record.ID] = cloneChallenge(record)
	return nil
}

func (repository *MemoryRepository) TakeChallenge(ctx context.Context, id string) (ChallengeRecord, error) {
	if err := ctx.Err(); err != nil {
		return ChallengeRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, exists := repository.challenges[id]
	if !exists {
		return ChallengeRecord{}, ErrNotFound
	}
	delete(repository.challenges, id)
	return cloneChallenge(record), nil
}

func (repository *MemoryRepository) SaveSession(ctx context.Context, record SessionRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.sessions[record.TokenDigest]; exists {
		return ErrConflict
	}
	if _, exists := repository.sessionIDs[record.ID]; exists {
		return ErrConflict
	}
	repository.sessions[record.TokenDigest] = record
	repository.sessionIDs[record.ID] = record.TokenDigest
	return nil
}

func (repository *MemoryRepository) LookupSession(ctx context.Context, digest string) (SessionRecord, error) {
	if err := ctx.Err(); err != nil {
		return SessionRecord{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	record, exists := repository.sessions[digest]
	if !exists {
		return SessionRecord{}, ErrNotFound
	}
	return record, nil
}

func (repository *MemoryRepository) RevokeSession(ctx context.Context, digest string, revokedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, exists := repository.sessions[digest]
	if !exists {
		return ErrNotFound
	}
	if record.RevokedAt.IsZero() {
		record.RevokedAt = revokedAt
		repository.sessions[digest] = record
	}
	return nil
}

func (repository *MemoryRepository) CheckAndStore(ctx context.Context, record ReplayRecord) (ReplayResult, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := record.SessionID + "\x00" + record.IdempotencyKey
	previous, exists := repository.replay[key]
	if !exists {
		repository.replay[key] = record
		return ReplayNew, nil
	}
	if previous.RequestDigest == record.RequestDigest {
		return ReplayExact, nil
	}
	return ReplayConflict, nil
}

func actorKey(organizationID, actorID string) string { return organizationID + "\x00" + actorID }

func cloneActor(actor localidentity.Actor) localidentity.Actor {
	cloned := actor
	cloned.Roles = append([]localidentity.Role(nil), actor.Roles...)
	cloned.Grants = make([]localidentity.ScopeGrant, len(actor.Grants))
	for index, grant := range actor.Grants {
		cloned.Grants[index] = grant
		cloned.Grants[index].CaseIDs = append([]string(nil), grant.CaseIDs...)
	}
	return cloned
}

func cloneChallenge(record ChallengeRecord) ChallengeRecord {
	cloned := record
	cloned.Message = append([]byte(nil), record.Message...)
	return cloned
}

var (
	_ ActorDirectory = (*MemoryRepository)(nil)
	_ ChallengeStore = (*MemoryRepository)(nil)
	_ SessionStore   = (*MemoryRepository)(nil)
	_ ReplayStore    = (*MemoryRepository)(nil)
)
