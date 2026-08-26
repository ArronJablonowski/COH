// Package auditsigner holds the active audit-checkpoint signing key and the
// public historical key revisions required for offline verification.
package auditsigner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/workflow/auditlog"
)

type Key struct {
	ID         string
	Revision   uint64
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	ValidFrom  time.Time
	ValidUntil time.Time
	RevokedAt  *time.Time
	Current    bool
}

type keyID struct {
	id       string
	revision uint64
}

type entry struct {
	authority auditlog.KeyAuthority
	private   ed25519.PrivateKey
	current   bool
}

type Keyring struct {
	mu      sync.RWMutex
	entries map[keyID]*entry
	current keyID
	random  io.Reader
	closed  bool
}

func New(keys []Key) (*Keyring, error) {
	if len(keys) == 0 || len(keys) > 64 {
		return nil, auditlog.ErrInvalidInput
	}
	keyring := &Keyring{entries: make(map[keyID]*entry, len(keys)), random: rand.Reader}
	currentCount := 0
	for _, key := range keys {
		identity := keyID{id: key.ID, revision: key.Revision}
		if !validToken(key.ID) || key.Revision == 0 || key.ValidFrom.IsZero() || key.ValidUntil.IsZero() ||
			!key.ValidFrom.Before(key.ValidUntil) || keyring.entries[identity] != nil {
			keyring.Destroy()
			return nil, auditlog.ErrInvalidInput
		}
		publicKey := append(ed25519.PublicKey(nil), key.PublicKey...)
		privateKey := append(ed25519.PrivateKey(nil), key.PrivateKey...)
		if len(privateKey) == ed25519.PrivateKeySize {
			derived := privateKey.Public().(ed25519.PublicKey)
			if len(publicKey) == 0 {
				publicKey = append(ed25519.PublicKey(nil), derived...)
			} else if !equal(publicKey, derived) {
				zero(privateKey)
				keyring.Destroy()
				return nil, auditlog.ErrInvalidInput
			}
		}
		if len(publicKey) != ed25519.PublicKeySize || key.Current && len(privateKey) != ed25519.PrivateKeySize ||
			!key.Current && len(privateKey) != 0 {
			zero(privateKey)
			keyring.Destroy()
			return nil, auditlog.ErrInvalidInput
		}
		revokedAt := cloneTime(key.RevokedAt)
		keyring.entries[identity] = &entry{authority: auditlog.KeyAuthority{KeyID: key.ID, Revision: key.Revision,
			PublicKey: publicKey, ValidFrom: key.ValidFrom.UTC(), ValidUntil: key.ValidUntil.UTC(), RevokedAt: revokedAt},
			private: privateKey, current: key.Current}
		if key.Current {
			currentCount++
			keyring.current = identity
		}
	}
	if currentCount != 1 {
		keyring.Destroy()
		return nil, auditlog.ErrInvalidInput
	}
	return keyring, nil
}

func (keyring *Keyring) SignAuditCheckpoint(ctx context.Context, draft tamperaudit.Checkpoint) (tamperaudit.Checkpoint, error) {
	if ctx == nil || ctx.Err() != nil {
		return tamperaudit.Checkpoint{}, auditlog.ErrUnavailable
	}
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	entry := keyring.entries[keyring.current]
	createdAt, err := time.Parse("2006-01-02T15:04:05.000000000Z", draft.CreatedAt)
	if err != nil || keyring.closed || entry == nil || !admitted(entry.authority, createdAt) {
		return tamperaudit.Checkpoint{}, auditlog.ErrUnavailable
	}
	draft.SigningKeyID, draft.SigningKeyRevision = entry.authority.KeyID, entry.authority.Revision
	draft.SignatureAlgorithm = tamperaudit.SignatureAlgorithm
	return tamperaudit.SignCheckpoint(draft, entry.private)
}

func (keyring *Keyring) ResolveAuditKey(ctx context.Context, id string, revision uint64) (auditlog.KeyAuthority, error) {
	if ctx == nil || ctx.Err() != nil {
		return auditlog.KeyAuthority{}, auditlog.ErrUnavailable
	}
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	entry := keyring.entries[keyID{id: id, revision: revision}]
	if keyring.closed || entry == nil {
		return auditlog.KeyAuthority{}, auditlog.ErrUnavailable
	}
	authority := entry.authority
	authority.PublicKey = append(ed25519.PublicKey(nil), authority.PublicKey...)
	authority.RevokedAt = cloneTime(authority.RevokedAt)
	return authority, nil
}

func (keyring *Keyring) NewAuditID(now time.Time) (string, error) {
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	if keyring.closed || now.IsZero() || now.UnixMilli() < 0 || now.UnixMilli() >= 1<<48 {
		return "", auditlog.ErrUnavailable
	}
	var value [16]byte
	if _, err := io.ReadFull(keyring.random, value[6:]); err != nil {
		return "", auditlog.ErrUnavailable
	}
	millis := uint64(now.UnixMilli())
	for index := 5; index >= 0; index-- {
		value[index] = byte(millis)
		millis >>= 8
	}
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func (keyring *Keyring) Destroy() {
	keyring.mu.Lock()
	defer keyring.mu.Unlock()
	if keyring.closed {
		return
	}
	for _, entry := range keyring.entries {
		zero(entry.private)
		entry.private = nil
	}
	keyring.closed = true
}

func admitted(authority auditlog.KeyAuthority, at time.Time) bool {
	return !at.Before(authority.ValidFrom) && at.Before(authority.ValidUntil) &&
		(authority.RevokedAt == nil || at.Before(authority.RevokedAt.UTC()))
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func equal(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyOfValue := value.UTC()
	return &copyOfValue
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
