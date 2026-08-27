package evidencelifecycle

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestImportServiceRejectsCoherentVerificationMutationsBeforeAuthority(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*importRig)
	}{
		{"manifest schema", func(rig *importRig) {
			rig.reader.value.Manifest.SchemaVersion = "coh.evidence-export-manifest/v0"
		}},
		{"case scope", func(rig *importRig) {
			rig.reader.value.Manifest.Case.CaseID = lifecycleUUID("substituted-case")
			rebindImportManifest(&rig.reader.value)
		}},
		{"header", func(rig *importRig) {
			rig.reader.value.Package.Header.Magic = "UNTRUSTED"
		}},
		{"package bounds", func(rig *importRig) {
			value := &rig.reader.value
			value.Package.Header.PackageLength = rig.command.Limits.MaximumPackageBytes + 1
			value.Package.Header.HeaderDigest = ""
			value.Package.Header.HeaderDigest, _ = HeaderBindingDigest(value.Package.Header)
			value.Package.HeaderDigest = value.Package.Header.HeaderDigest
			value.Package.PackageLength = value.Package.Header.PackageLength
			value.Verification.HeaderDigest = value.Package.HeaderDigest
			rebindImportVerification(&value.Verification)
		}},
		{"signing key revision", func(rig *importRig) {
			value := &rig.reader.value
			value.Signature.KeyRevision++
			value.Package.SignatureDigest, _ = SignatureBindingDigest(value.Signature)
			value.Verification.SignatureDigest = value.Package.SignatureDigest
			value.Verification.SigningKeyRevision = value.Signature.KeyRevision
			rebindImportVerification(&value.Verification)
		}},
		{"lineage", func(rig *importRig) {
			rig.reader.value.Verification.LineageDigest = lifecycleDigest("substituted-lineage")
			rebindImportVerification(&rig.reader.value.Verification)
		}},
		{"checkpoint", func(rig *importRig) {
			rig.reader.value.Verification.AuditCheckpointDigest = lifecycleDigest("substituted-checkpoint")
			rebindImportVerification(&rig.reader.value.Verification)
		}},
		{"stale verification", func(rig *importRig) {
			rig.reader.value.Verification.VerifiedAt = rig.reader.value.Manifest.ValidUntil
			rebindImportVerification(&rig.reader.value.Verification)
		}},
		{"staged artifact", func(rig *importRig) {
			rig.reader.value.Staged[0].ArtifactDigest = lifecycleDigest("substituted-artifact")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newImportRig(t)
			test.mutate(rig)
			result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
			if CodeOf(err) != Denied || len(result.Imported) != 0 || containsCall(rig.calls, "authority") ||
				containsCall(rig.calls, "store.quarantined") || containsCall(rig.calls, "publish") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestImportServiceFailsClosedForHostilePackageReaderFindings(t *testing.T) {
	for _, reason := range []string{"archive_traversal", "archive_link", "archive_duplicate",
		"archive_bomb", "unknown_media_type", "trailing_data", "truncated_input"} {
		t.Run(reason, func(t *testing.T) {
			rig := newImportRig(t)
			rig.command.Deadline = time.Now().Add(time.Hour).UTC()
			rig.reader.err = newError(Denied, reason, false, nil)
			result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
			if CodeOf(err) != Denied || Reason(err) != reason || len(result.Imported) != 0 ||
				containsCall(rig.calls, "store.quarantined") || containsCall(rig.calls, "authority") ||
				containsCall(rig.calls, "publish") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestImportServiceRejectsStaleOrRevokedAuthorityAndRedactsDependencyErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Decision)
	}{
		{"stale policy", func(value *Decision) { value.PolicyDigest = lifecycleDigest("stale-policy") }},
		{"stale actor", func(value *Decision) { value.ActorRevision++ }},
		{"stale case", func(value *Decision) { value.ExpectedCaseRevision++ }},
		{"stale custody", func(value *Decision) { value.ExpectedCustodyHead.ChainHash = lifecycleDigest("stale-head") }},
		{"revoked", func(value *Decision) { value.Outcome, value.ReasonCode = Deny, ReasonRevoked }},
		{"expired", func(value *Decision) { value.ExpiresAt = lifecycleTestNow }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newImportRig(t)
			rig.authority.mutate = test.mutate
			result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
			if CodeOf(err) != Denied || len(result.Imported) != 0 || containsCall(rig.calls, "publish") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}

	rig := newImportRig(t)
	rig.command.Deadline = time.Now().Add(time.Hour).UTC()
	secret := "raw-package-secret"
	rig.reader.err = errors.New(secret)
	result, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1")
	if CodeOf(err) != Unavailable || len(result.Imported) != 0 || strings.Contains(err.Error(), secret) ||
		strings.Contains(err.Error(), "quarantine.import.1") || containsCall(rig.calls, "authority") {
		t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
	}
}

func rebindImportManifest(value *VerifiedImport) {
	value.Manifest.ManifestDigest = ""
	value.Manifest.ManifestDigest, _ = ManifestBindingDigest(value.Manifest)
	value.Signature.ManifestDigest = value.Manifest.ManifestDigest
	value.Package.ManifestDigest = value.Manifest.ManifestDigest
	value.Verification.ManifestDigest = value.Manifest.ManifestDigest
	value.Package.SignatureDigest, _ = SignatureBindingDigest(value.Signature)
	value.Verification.SignatureDigest = value.Package.SignatureDigest
	rebindImportVerification(&value.Verification)
}

func rebindImportVerification(value *ImportVerification) {
	value.ReportDigest = ""
	value.ReportDigest, _ = VerificationBindingDigest(*value)
}
