package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/profileactivation"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

func (store *Store) LoadActive(ctx context.Context, profileID string,
	target profileactivation.Target) (profileactivation.ActiveProfile, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "profile_active_load"); err != nil {
		return profileactivation.ActiveProfile{}, false, err
	}
	return store.loadActive(ctx, store.db, profileID, target)
}

func (store *Store) LoadTransition(ctx context.Context, transitionID string) (profileactivation.Transition, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "profile_transition_load"); err != nil {
		return profileactivation.Transition{}, false, err
	}
	return store.loadProfileTransition(ctx, store.db, transitionID)
}

func (store *Store) CreateTransition(ctx context.Context,
	value profileactivation.Transition) (profileactivation.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "profile_transition_create"); err != nil {
		return profileactivation.Transition{}, err
	}
	canonical, digest, err := profileactivation.CanonicalTransition(ctx, value)
	if err != nil {
		return profileactivation.Transition{}, storageError(workflow.StorageInvalidInput,
			"profile_transition_create", "transition", "transition is invalid")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return profileactivation.Transition{}, normalizeError("profile_transition_create", "transaction", err)
	}
	defer tx.Rollback()
	target := value.Candidate.Target
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO coh_profile_activation_transitions
(transition_id,profile_id,deployment_kind,connectivity_mode,platform,surface,phase,sequence,intent_digest,transition_digest,canonical)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, value.TransitionID, value.Candidate.ProfileID, target.DeploymentKind,
		target.ConnectivityMode, target.Platform, target.Surface, value.Phase, value.Sequence,
		value.IntentDigest, digest, canonical)
	if err != nil {
		return profileactivation.Transition{}, normalizeError("profile_transition_create", "insert", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		existing, found, loadErr := store.loadProfileTransition(ctx, tx, value.TransitionID)
		if loadErr != nil || !found {
			return profileactivation.Transition{}, normalizeError("profile_transition_create", "replay", loadErr)
		}
		if existing.IntentDigest != value.IntentDigest {
			return profileactivation.Transition{}, storageError(workflow.StorageConflict,
				"profile_transition_create", "transition_id", "transition identity was reused")
		}
		return existing, nil
	}
	if err := tx.Commit(); err != nil {
		return profileactivation.Transition{}, normalizeError("profile_transition_create", "commit", err)
	}
	sealed, err := profileactivation.DecodeTransition(ctx, canonical)
	return sealed, err
}

func (store *Store) AdvanceTransition(ctx context.Context, transitionID string, expectedSequence uint64,
	expectedDigest string, phase profileactivation.Phase, quiescenceDigest string) (profileactivation.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "profile_transition_advance"); err != nil {
		return profileactivation.Transition{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return profileactivation.Transition{}, normalizeError("profile_transition_advance", "transaction", err)
	}
	defer tx.Rollback()
	current, found, err := store.loadProfileTransition(ctx, tx, transitionID)
	if err != nil || !found {
		return profileactivation.Transition{}, storageError(workflow.StorageConflict,
			"profile_transition_advance", "transition", "transition is unavailable")
	}
	allowed := current.Phase == profileactivation.Prepared && phase == profileactivation.Quiescent ||
		current.Phase == profileactivation.Published && phase == profileactivation.Active
	if current.Sequence != expectedSequence || current.TransitionDigest != expectedDigest || !allowed ||
		phase == profileactivation.Quiescent && quiescenceDigest == "" ||
		phase == profileactivation.Active && quiescenceDigest != current.QuiescenceDigest {
		return profileactivation.Transition{}, storageError(workflow.StorageConflict,
			"profile_transition_advance", "state", "transition state changed")
	}
	current.Phase = phase
	current.Sequence++
	current.QuiescenceDigest = quiescenceDigest
	current.UpdatedAt = formatProfileActivationTime(store.clock())
	current.TransitionDigest = ""
	canonical, digest, err := profileactivation.CanonicalTransition(ctx, current)
	if err != nil {
		return profileactivation.Transition{}, storageError(workflow.StorageDenied,
			"profile_transition_advance", "transition", "transition update is invalid")
	}
	result, err := tx.ExecContext(ctx, `UPDATE coh_profile_activation_transitions SET
phase=?,sequence=?,transition_digest=?,canonical=? WHERE transition_id=? AND sequence=? AND transition_digest=?`,
		current.Phase, current.Sequence, digest, canonical, transitionID, expectedSequence, expectedDigest)
	if err != nil {
		return profileactivation.Transition{}, normalizeError("profile_transition_advance", "update", err)
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return profileactivation.Transition{}, storageError(workflow.StorageConflict,
			"profile_transition_advance", "state", "transition state changed")
	}
	if err := tx.Commit(); err != nil {
		return profileactivation.Transition{}, normalizeError("profile_transition_advance", "commit", err)
	}
	return profileactivation.DecodeTransition(ctx, canonical)
}

func (store *Store) Publish(ctx context.Context, transitionID string, expectedSequence uint64,
	expectedDigest string, active profileactivation.ActiveProfile,
	quiescenceDigest string) (profileactivation.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "profile_publish"); err != nil {
		return profileactivation.Transition{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return profileactivation.Transition{}, normalizeError("profile_publish", "transaction", err)
	}
	defer tx.Rollback()
	transition, found, err := store.loadProfileTransition(ctx, tx, transitionID)
	if err != nil || !found || transition.Phase != profileactivation.Quiescent ||
		transition.Sequence != expectedSequence || transition.TransitionDigest != expectedDigest ||
		transition.QuiescenceDigest != quiescenceDigest || active.TransitionID != transitionID ||
		!activeMatchesCandidate(active, transition.Candidate) {
		return profileactivation.Transition{}, storageError(workflow.StorageConflict,
			"profile_publish", "transition", "publication binding changed")
	}
	current, activeFound, err := store.loadActive(ctx, tx, active.ProfileID, active.Target)
	if err != nil {
		return profileactivation.Transition{}, err
	}
	if !activeFound && transition.ExpectedActiveRevision != 0 || activeFound &&
		(current.ProfileRevision != transition.ExpectedActiveRevision ||
			current.CompositionDigest != transition.ExpectedCompositionDigest) {
		return profileactivation.Transition{}, storageError(workflow.StorageConflict,
			"profile_publish", "active_profile", "active profile changed")
	}
	active.ActiveDigest = ""
	activeCanonical, activeDigest, err := profileactivation.CanonicalActive(ctx, active)
	if err != nil {
		return profileactivation.Transition{}, storageError(workflow.StorageDenied,
			"profile_publish", "active_profile", "active profile is invalid")
	}
	target := active.Target
	if _, err := tx.ExecContext(ctx, `INSERT INTO coh_active_profiles
(profile_id,deployment_kind,connectivity_mode,platform,surface,profile_revision,composition_digest,transition_id,active_digest,canonical)
VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(profile_id,deployment_kind,connectivity_mode,platform,surface)
DO UPDATE SET profile_revision=excluded.profile_revision,composition_digest=excluded.composition_digest,
transition_id=excluded.transition_id,active_digest=excluded.active_digest,canonical=excluded.canonical`,
		active.ProfileID, target.DeploymentKind, target.ConnectivityMode, target.Platform, target.Surface,
		active.ProfileRevision, active.CompositionDigest, transitionID, activeDigest, activeCanonical); err != nil {
		return profileactivation.Transition{}, normalizeError("profile_publish", "active_profile", err)
	}
	transition.Phase = profileactivation.Published
	transition.Sequence++
	transition.UpdatedAt = formatProfileActivationTime(store.clock())
	transition.TransitionDigest = ""
	transitionCanonical, transitionDigest, err := profileactivation.CanonicalTransition(ctx, transition)
	if err != nil {
		return profileactivation.Transition{}, storageError(workflow.StorageDenied,
			"profile_publish", "transition", "published transition is invalid")
	}
	result, err := tx.ExecContext(ctx, `UPDATE coh_profile_activation_transitions SET
phase=?,sequence=?,transition_digest=?,canonical=? WHERE transition_id=? AND sequence=? AND transition_digest=?`,
		transition.Phase, transition.Sequence, transitionDigest, transitionCanonical,
		transitionID, expectedSequence, expectedDigest)
	if err != nil {
		return profileactivation.Transition{}, normalizeError("profile_publish", "transition", err)
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return profileactivation.Transition{}, storageError(workflow.StorageConflict,
			"profile_publish", "transition", "transition state changed")
	}
	if err := tx.Commit(); err != nil {
		return profileactivation.Transition{}, normalizeError("profile_publish", "commit", err)
	}
	return profileactivation.DecodeTransition(ctx, transitionCanonical)
}

type profileActivationQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (store *Store) loadProfileTransition(ctx context.Context, query profileActivationQuerier,
	transitionID string) (profileactivation.Transition, bool, error) {
	var profileID, deployment, connectivity, platform, surface, phase, intent, digest string
	var sequence int64
	var canonical []byte
	err := query.QueryRowContext(ctx, `SELECT profile_id,deployment_kind,connectivity_mode,platform,surface,
phase,sequence,intent_digest,transition_digest,canonical FROM coh_profile_activation_transitions WHERE transition_id=?`,
		transitionID).Scan(&profileID, &deployment, &connectivity, &platform, &surface, &phase,
		&sequence, &intent, &digest, &canonical)
	if err == sql.ErrNoRows {
		return profileactivation.Transition{}, false, nil
	}
	if err != nil {
		return profileactivation.Transition{}, false, normalizeError("profile_transition_load", "query", err)
	}
	value, err := profileactivation.DecodeTransition(ctx, canonical)
	if err != nil || sequence <= 0 || value.TransitionID != transitionID || value.Candidate.ProfileID != profileID ||
		value.Candidate.Target != (profileactivation.Target{DeploymentKind: deployment, ConnectivityMode: connectivity,
			Platform: platform, Surface: surface}) || string(value.Phase) != phase || value.Sequence != uint64(sequence) ||
		value.IntentDigest != intent || value.TransitionDigest != digest {
		return profileactivation.Transition{}, false, storageError(workflow.StorageDenied,
			"profile_transition_load", "integrity", "stored transition failed verification")
	}
	return value, true, nil
}

func (store *Store) loadActive(ctx context.Context, query profileActivationQuerier, profileID string,
	target profileactivation.Target) (profileactivation.ActiveProfile, bool, error) {
	var revision int64
	var composition, transitionID, digest string
	var canonical []byte
	err := query.QueryRowContext(ctx, `SELECT profile_revision,composition_digest,transition_id,active_digest,canonical
FROM coh_active_profiles WHERE profile_id=? AND deployment_kind=? AND connectivity_mode=? AND platform=? AND surface=?`,
		profileID, target.DeploymentKind, target.ConnectivityMode, target.Platform, target.Surface).
		Scan(&revision, &composition, &transitionID, &digest, &canonical)
	if err == sql.ErrNoRows {
		return profileactivation.ActiveProfile{}, false, nil
	}
	if err != nil {
		return profileactivation.ActiveProfile{}, false, normalizeError("profile_active_load", "query", err)
	}
	value, err := profileactivation.DecodeActive(ctx, canonical)
	if err != nil || revision <= 0 || value.ProfileID != profileID || value.Target != target ||
		value.ProfileRevision != uint64(revision) || value.CompositionDigest != composition ||
		value.TransitionID != transitionID || value.ActiveDigest != digest {
		return profileactivation.ActiveProfile{}, false, storageError(workflow.StorageDenied,
			"profile_active_load", "integrity", "stored active profile failed verification")
	}
	return value, true, nil
}

func activeMatchesCandidate(active profileactivation.ActiveProfile, candidate profileactivation.Candidate) bool {
	return active.ProfileID == candidate.ProfileID && active.ProfileRevision == candidate.ProfileRevision &&
		active.Target == candidate.Target && active.ProfileBindingDigest == candidate.ProfileBindingDigest &&
		active.CompositionDigest == candidate.CompositionDigest &&
		active.CapabilityGraphDigest == candidate.CapabilityGraphDigest &&
		active.InspectionDigest == candidate.InspectionDigest
}

func formatProfileActivationTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

var _ profileactivation.Store = (*Store)(nil)
