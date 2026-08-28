package capabilityseam

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestQualificationAuthorityFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		bundle    func(*testing.T) ValidatedBundle
		authority func(ValidatedBundle) QualificationAuthoritySnapshot
		reason    string
	}{
		{"snapshot_expired", decodeFixtureBundle, func(bundle ValidatedBundle) QualificationAuthoritySnapshot {
			value := authorityFor(bundle)
			value.ValidUntil = qualificationTestTime
			return value
		}, "qualification_authority_stale"},
		{"snapshot_from_future", decodeFixtureBundle, func(bundle ValidatedBundle) QualificationAuthoritySnapshot {
			value := authorityFor(bundle)
			value.ObservedAt = qualificationTestTime.Add(time.Second)
			value.ValidUntil = qualificationTestTime.Add(time.Minute)
			return value
		}, "qualification_authority_stale"},
		{"snapshot_too_long", decodeFixtureBundle, func(bundle ValidatedBundle) QualificationAuthoritySnapshot {
			value := authorityFor(bundle)
			value.ValidUntil = value.ObservedAt.Add(maximumAuthorityValidity + time.Nanosecond)
			return value
		}, "qualification_authority_stale"},
		{"profile_drift", decodeFixtureBundle, func(bundle ValidatedBundle) QualificationAuthoritySnapshot {
			value := authorityFor(bundle)
			value.ProfileDigest = digestOf("9")
			return value
		}, "composition_authority_stale"},
		{"record_missing", decodeFixtureBundle, func(bundle ValidatedBundle) QualificationAuthoritySnapshot {
			value := authorityFor(bundle)
			value.Records = nil
			return value
		}, "qualification_authority_incomplete"},
		{"record_order", bundleWithTokenizerDependency, func(bundle ValidatedBundle) QualificationAuthoritySnapshot {
			value := authorityFor(bundle)
			slices.Reverse(value.Records)
			return value
		}, "qualification_authority_order"},
		{"duplicate_record_id", bundleWithTokenizerDependency, func(bundle ValidatedBundle) QualificationAuthoritySnapshot {
			value := authorityFor(bundle)
			value.Records[1].RecordID = value.Records[0].RecordID
			return value
		}, "qualification_authority_ambiguous"},
		{"record_registry_revision", decodeFixtureBundle, mutateAuthorityRecord(func(record *QualificationAuthorityRecord) {
			record.RegistryRevision++
		}), "qualification_authority_record"},
		{"record_inactive", decodeFixtureBundle, mutateAuthorityRecord(func(record *QualificationAuthorityRecord) {
			record.Active = false
		}), "qualification_revoked"},
		{"record_revoked", decodeFixtureBundle, mutateAuthorityRecord(func(record *QualificationAuthorityRecord) {
			record.RevocationRevision = 2
		}), "qualification_revoked"},
		{"record_digest_drift", decodeFixtureBundle, mutateAuthorityRecord(func(record *QualificationAuthorityRecord) {
			record.RecordDigest = digestOf("9")
		}), "qualification_authority_drift"},
		{"artifact_drift", decodeFixtureBundle, mutateAuthorityRecord(func(record *QualificationAuthorityRecord) {
			record.ProviderArtifactDigest = digestOf("9")
		}), "qualification_authority_drift"},
		{"capability_drift", decodeFixtureBundle, mutateAuthorityRecord(func(record *QualificationAuthorityRecord) {
			record.Capability.Version = "2.0.0"
		}), "qualification_authority_drift"},
		{"authority_revision_drift", decodeFixtureBundle, mutateAuthorityRecord(func(record *QualificationAuthorityRecord) {
			record.AuthorityRevision++
		}), "qualification_authority_drift"},
		{"validity_drift", decodeFixtureBundle, mutateAuthorityRecord(func(record *QualificationAuthorityRecord) {
			record.ExpiresAt = "2026-09-26T00:00:00Z"
		}), "qualification_authority_drift"},
		{"qualification_expired", expiredQualificationBundle, authorityFor, "qualification_expired"},
		{"qualification_not_yet_valid", futureQualificationBundle, authorityFor, "qualification_expired"},
		{"declared_revocation", revokedQualificationBundle, authorityFor, "qualification_revoked"},
	}
	resolver, err := NewResolver(fixedClock{now: qualificationTestTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := test.bundle(t)
			_, err := resolver.Resolve(context.Background(), bundle, test.authority(bundle))
			if Code(err) != Denied || Reason(err) != test.reason {
				t.Fatalf("code=%s reason=%s err=%v", Code(err), Reason(err), err)
			}
		})
	}
}

func TestResolverRequiresTrustedClockAndAuthority(t *testing.T) {
	if resolver, err := NewResolver(nil); resolver != nil || Code(err) != InvalidInput {
		t.Fatalf("nil clock: resolver=%v err=%v", resolver, err)
	}
	var resolver *Resolver
	bundle := decodeFixtureBundle(t)
	if _, err := resolver.Resolve(context.Background(), bundle, authorityFor(bundle)); Code(err) != InvalidInput || Reason(err) != "resolver_clock_required" {
		t.Fatalf("nil resolver: %v", err)
	}
	validResolver, _ := NewResolver(fixedClock{now: qualificationTestTime})
	if _, err := validResolver.Resolve(context.Background(), bundle, QualificationAuthoritySnapshot{}); Code(err) != Denied {
		t.Fatalf("empty authority: %v", err)
	}
}

func mutateAuthorityRecord(mutate func(*QualificationAuthorityRecord)) func(ValidatedBundle) QualificationAuthoritySnapshot {
	return func(bundle ValidatedBundle) QualificationAuthoritySnapshot {
		value := authorityFor(bundle)
		mutate(&value.Records[0])
		return value
	}
}

func expiredQualificationBundle(t *testing.T) ValidatedBundle {
	return mutateValidBundle(t, func(value *Bundle) {
		value.Providers[0].Qualification.IssuedAt = "2026-08-26T00:00:00Z"
		value.Providers[0].Qualification.ExpiresAt = "2026-08-27T00:00:00Z"
	})
}

func futureQualificationBundle(t *testing.T) ValidatedBundle {
	return mutateValidBundle(t, func(value *Bundle) {
		value.Providers[0].Qualification.IssuedAt = "2026-08-29T00:00:00Z"
		value.Providers[0].Qualification.ExpiresAt = "2026-08-30T00:00:00Z"
	})
}

func revokedQualificationBundle(t *testing.T) ValidatedBundle {
	return mutateValidBundle(t, func(value *Bundle) {
		value.Providers[0].Qualification.Status = "revoked"
		value.Providers[0].Qualification.RevocationRevision = 2
	})
}
