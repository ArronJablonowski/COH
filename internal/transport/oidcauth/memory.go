package oidcauth

import (
	"context"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

type ActorBinding struct {
	Issuer  string
	Subject string
	Actor   localidentity.Actor
}

type MemoryRepository struct {
	mu         sync.RWMutex
	actors     map[string]localidentity.Actor
	bindings   map[string]string
	states     map[string]LoginStateRecord
	sessions   map[string]SessionRecord
	sessionIDs map[string]string
	replay     map[string]ReplayRecord
}

func NewMemoryRepository(bindings []ActorBinding) (*MemoryRepository, error) {
	repository := &MemoryRepository{actors: make(map[string]localidentity.Actor), bindings: make(map[string]string),
		states: make(map[string]LoginStateRecord), sessions: make(map[string]SessionRecord),
		sessionIDs: make(map[string]string), replay: make(map[string]ReplayRecord)}
	for _, binding := range bindings {
		if binding.Issuer == "" || binding.Subject == "" || localidentity.ValidateActor(binding.Actor) != nil {
			return nil, authError(localidentity.InvalidInput, "actor_binding_invalid")
		}
		actorKey := binding.Actor.OrganizationID + "\x00" + binding.Actor.ID
		bindingKey := binding.Issuer + "\x00" + binding.Subject
		if _, exists := repository.bindings[bindingKey]; exists {
			return nil, authError(localidentity.Conflict, "actor_binding_conflict")
		}
		if previous, exists := repository.actors[actorKey]; exists && previous.Revision != binding.Actor.Revision {
			return nil, authError(localidentity.Conflict, "actor_binding_conflict")
		}
		repository.actors[actorKey] = cloneActor(binding.Actor)
		repository.bindings[bindingKey] = actorKey
	}
	return repository, nil
}

func (repository *MemoryRepository) LookupOIDCActor(ctx context.Context, issuer, subject string) (localidentity.Actor, error) {
	if err := ctx.Err(); err != nil {
		return localidentity.Actor{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	actorKey, exists := repository.bindings[issuer+"\x00"+subject]
	if !exists {
		return localidentity.Actor{}, ErrNotFound
	}
	return cloneActor(repository.actors[actorKey]), nil
}

func (repository *MemoryRepository) LookupActor(ctx context.Context, organizationID, actorID string) (localidentity.Actor, error) {
	if err := ctx.Err(); err != nil {
		return localidentity.Actor{}, err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	actor, exists := repository.actors[organizationID+"\x00"+actorID]
	if !exists {
		return localidentity.Actor{}, ErrNotFound
	}
	return cloneActor(actor), nil
}

func (repository *MemoryRepository) ReplaceActor(ctx context.Context, actor localidentity.Actor) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := localidentity.ValidateActor(actor); err != nil {
		return authError(localidentity.InvalidInput, "actor_invalid")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := actor.OrganizationID + "\x00" + actor.ID
	current, exists := repository.actors[key]
	if !exists || actor.Revision != current.Revision+1 {
		return authError(localidentity.Conflict, "actor_revision_conflict")
	}
	repository.actors[key] = cloneActor(actor)
	return nil
}

func (repository *MemoryRepository) SaveLoginState(ctx context.Context, record LoginStateRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.states[record.ID]; exists {
		return ErrConflict
	}
	repository.states[record.ID] = record
	return nil
}

func (repository *MemoryRepository) TakeLoginState(ctx context.Context, id string) (LoginStateRecord, error) {
	if err := ctx.Err(); err != nil {
		return LoginStateRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, exists := repository.states[id]
	if !exists {
		return LoginStateRecord{}, ErrNotFound
	}
	delete(repository.states, id)
	return record, nil
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

var (
	_ ActorDirectory = (*MemoryRepository)(nil)
	_ StateStore     = (*MemoryRepository)(nil)
	_ SessionStore   = (*MemoryRepository)(nil)
	_ ReplayStore    = (*MemoryRepository)(nil)
)
