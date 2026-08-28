package capabilityseam

import (
	"slices"
	"time"
)

const maximumAuthorityValidity = 5 * time.Minute

// Clock is a trusted composition-root dependency. Model, profile, provider,
// and extension data cannot supply it.
type Clock interface {
	Now() time.Time
}

type Resolver struct {
	clock Clock
}

func NewResolver(clock Clock) (*Resolver, error) {
	if clock == nil {
		return nil, newError(InvalidInput, "resolver_clock_required")
	}
	return &Resolver{clock: clock}, nil
}

// QualificationAuthoritySnapshot is trusted live registry state, not a public
// JSON contract. It contains identity and digest metadata only.
type QualificationAuthoritySnapshot struct {
	ProfileDigest string
	Revision      uint64
	ObservedAt    time.Time
	ValidUntil    time.Time
	Records       []QualificationAuthorityRecord
}

type QualificationAuthorityRecord struct {
	RecordID               string
	RecordDigest           string
	ProviderID             string
	ProviderVersion        string
	ProviderArtifactDigest string
	Capability             CapabilityRef
	ProfileDigest          string
	IssuedAt               string
	ExpiresAt              string
	RegistryRevision       uint64
	AuthorityRevision      uint64
	RevocationRevision     uint64
	Active                 bool
}

func validateQualificationAuthority(now time.Time, bundle Bundle, selected map[string]Provider,
	authority QualificationAuthoritySnapshot) error {
	now = now.UTC()
	if now.IsZero() || !validDigest(authority.ProfileDigest) || authority.ProfileDigest != bundle.ProfileDigest ||
		authority.Revision == 0 || authority.ObservedAt.IsZero() || authority.ValidUntil.IsZero() ||
		authority.ObservedAt.Location() != time.UTC || authority.ValidUntil.Location() != time.UTC ||
		authority.ValidUntil.Sub(authority.ObservedAt) <= 0 ||
		authority.ValidUntil.Sub(authority.ObservedAt) > maximumAuthorityValidity ||
		now.Before(authority.ObservedAt) || !now.Before(authority.ValidUntil) {
		return newError(Denied, "qualification_authority_stale")
	}
	if len(authority.Records) != len(selected) {
		return newError(Denied, "qualification_authority_incomplete")
	}
	records := make(map[string]QualificationAuthorityRecord, len(authority.Records))
	recordIDs := make(map[string]struct{}, len(authority.Records))
	ordered := make([]string, len(authority.Records))
	for index, record := range authority.Records {
		identity := record.ProviderID + "@" + record.ProviderVersion
		if !validToken(record.ProviderID, 128) || !semverPattern.MatchString(record.ProviderVersion) ||
			!validDigest(record.ProviderArtifactDigest) || !validCapability(record.Capability) ||
			!uuid7Pattern.MatchString(record.RecordID) || !validDigest(record.RecordDigest) ||
			record.ProfileDigest != authority.ProfileDigest || record.RegistryRevision != authority.Revision ||
			record.AuthorityRevision == 0 {
			return newError(Denied, "qualification_authority_record")
		}
		if _, exists := recordIDs[record.RecordID]; exists {
			return newError(Denied, "qualification_authority_ambiguous")
		}
		if _, exists := records[identity]; exists {
			return newError(Denied, "qualification_authority_ambiguous")
		}
		records[identity] = record
		recordIDs[record.RecordID] = struct{}{}
		ordered[index] = identity
	}
	if !slices.IsSorted(ordered) {
		return newError(Denied, "qualification_authority_order")
	}
	for _, provider := range bundle.Providers {
		if err := admitProviderQualification(now, provider, records); err != nil {
			return err
		}
	}
	return nil
}

func admitProviderQualification(now time.Time, provider Provider,
	records map[string]QualificationAuthorityRecord) error {
	qualification := provider.Qualification
	issued, issuedErr := time.Parse(time.RFC3339Nano, qualification.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, qualification.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || now.Before(issued) || !now.Before(expires) {
		return newError(Denied, "qualification_expired")
	}
	record, exists := records[provider.ProviderID+"@"+provider.ProviderVersion]
	if !exists {
		return newError(Denied, "qualification_authority_missing")
	}
	if !record.Active || record.RevocationRevision != 0 || qualification.Status != "qualified" ||
		qualification.RevocationRevision != 0 {
		return newError(Denied, "qualification_revoked")
	}
	if record.RecordID != qualification.RecordID || record.RecordDigest != qualification.RecordDigest ||
		record.ProviderArtifactDigest != provider.ArtifactDigest ||
		record.Capability != provider.Capability || record.ProfileDigest != qualification.ProfileDigest ||
		record.IssuedAt != qualification.IssuedAt || record.ExpiresAt != qualification.ExpiresAt ||
		record.AuthorityRevision != qualification.AuthorityRevision {
		return newError(Denied, "qualification_authority_drift")
	}
	return nil
}
