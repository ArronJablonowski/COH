package providercontract

import (
	"context"
	"sync"
	"time"
)

type QualificationAdmission struct {
	QualificationID     string
	QualificationDigest string
	EnvelopeDigest      string
	QualifierKeyID      string
	KeyRevision         uint64
	ApprovalRevision    uint64
	Replayed            bool
}

type QualificationRegistry struct {
	mu      sync.RWMutex
	records map[string]VerifiedQualification
}

func NewQualificationRegistry() *QualificationRegistry {
	return &QualificationRegistry{records: make(map[string]VerifiedQualification)}
}

func (registry *QualificationRegistry) Admit(ctx context.Context, capability ValidatedCapability,
	verified VerifiedQualification, now time.Time) (QualificationAdmission, error) {
	if err := contextError(ctx); err != nil {
		return QualificationAdmission{}, err
	}
	if registry == nil || registry.records == nil || verified.EnvelopeDigest() == "" {
		return QualificationAdmission{}, NewError(InvalidInput, "qualification_registry")
	}
	qualification := verified.Qualification()
	if err := AdmitQualification(capability, qualification, now); err != nil {
		return QualificationAdmission{}, err
	}
	value := qualification.Value()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if existing, exists := registry.records[value.QualificationID]; exists {
		if existing.EnvelopeDigest() != verified.EnvelopeDigest() {
			return QualificationAdmission{}, NewError(Conflict, "qualification_id_collision")
		}
		return admission(existing, true), nil
	}
	registry.records[value.QualificationID] = cloneVerified(verified)
	return admission(verified, false), nil
}

func (registry *QualificationRegistry) Resolve(ctx context.Context, qualificationID string,
	capability ValidatedCapability, now time.Time) (VerifiedQualification, error) {
	if err := contextError(ctx); err != nil {
		return VerifiedQualification{}, err
	}
	if registry == nil || registry.records == nil || !uuidPattern.MatchString(qualificationID) {
		return VerifiedQualification{}, NewError(InvalidInput, "qualification_registry")
	}
	registry.mu.RLock()
	verified, exists := registry.records[qualificationID]
	registry.mu.RUnlock()
	if !exists {
		return VerifiedQualification{}, NewError(Unsupported, "qualification_not_found")
	}
	if err := AdmitQualification(capability, verified.Qualification(), now); err != nil {
		return VerifiedQualification{}, err
	}
	return cloneVerified(verified), nil
}

func admission(verified VerifiedQualification, replayed bool) QualificationAdmission {
	qualification := verified.Qualification()
	return QualificationAdmission{QualificationID: qualification.Value().QualificationID,
		QualificationDigest: qualification.Digest(), EnvelopeDigest: verified.EnvelopeDigest(),
		QualifierKeyID: verified.KeyID(), KeyRevision: verified.KeyRevision(),
		ApprovalRevision: verified.ApprovalRevision(), Replayed: replayed}
}

func cloneVerified(value VerifiedQualification) VerifiedQualification {
	return VerifiedQualification{qualification: value.Qualification(), envelopeBytes: value.CanonicalEnvelopeBytes(),
		envelopeDigest: value.EnvelopeDigest(), keyID: value.KeyID(), keyRevision: value.KeyRevision(),
		approvalRevision: value.ApprovalRevision()}
}
