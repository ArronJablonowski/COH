package evidencelifecycle

import (
	"context"
	"testing"
)

func TestExportServiceRejectsStaleRevokedAndSubstitutedAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Decision)
	}{
		{"policy", func(value *Decision) { value.PolicyDigest = lifecycleDigest("stale-policy") }},
		{"approval", func(value *Decision) { value.ApprovalDigest = pointerDigest("stale-approval") }},
		{"actor", func(value *Decision) { value.ActorRevision++ }},
		{"case", func(value *Decision) { value.ExpectedCaseRevision++ }},
		{"custody", func(value *Decision) { value.ExpectedCustodyHead.ChainHash = lifecycleDigest("stale-head") }},
		{"revoked", func(value *Decision) { value.Outcome, value.ReasonCode = Deny, ReasonRevoked }},
		{"expired", func(value *Decision) { value.ExpiresAt = lifecycleTestNow }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newExportRig(t)
			rig.authority.mutate = test.mutate
			result, err := rig.service.Execute(t.Context(), rig.command)
			if CodeOf(err) != Denied || result.ReleaseReference != nil || containsCall(rig.calls, "custody.authorized") ||
				containsCall(rig.calls, "sign") || containsCall(rig.calls, "package.build") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestExportServiceRejectsSignatureAndPackageSubstitutionBeforeRelease(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*exportRig)
	}{
		{"signature key", func(rig *exportRig) {
			rig.signer.mutate = func(value *DetachedSignature) { value.KeyRevision++ }
		}},
		{"signature manifest", func(rig *exportRig) {
			rig.signer.mutate = func(value *DetachedSignature) { value.ManifestDigest = lifecycleDigest("substituted") }
		}},
		{"signature verification", func(rig *exportRig) {
			rig.verifier.err = newError(Denied, string(ReasonRevoked), false, nil)
		}},
		{"package manifest", func(rig *exportRig) {
			rig.packages.mutate = func(value *QuarantinedPackage) { value.ManifestDigest = lifecycleDigest("substituted") }
		}},
		{"package bounds", func(rig *exportRig) {
			rig.packages.mutate = func(value *QuarantinedPackage) {
				value.PackageLength = rig.command.Limits.MaximumPackageBytes + 1
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newExportRig(t)
			test.mutate(rig)
			result, err := rig.service.Execute(t.Context(), rig.command)
			if err == nil || result.ReleaseReference != nil || containsCall(rig.calls, "custody.completed") ||
				containsCall(rig.calls, "case.export") || containsCall(rig.calls, "store.commit") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestExportServiceCancellationAndTimeoutReleaseNoPackage(t *testing.T) {
	for _, test := range []struct {
		name string
		ctx  func() context.Context
		code ErrorCode
	}{
		{"canceled", func() context.Context {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx
		}, Canceled},
		{"timeout", func() context.Context { return t.Context() }, Timeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newExportRig(t)
			rig.signer.err = context.Canceled
			if test.code == Timeout {
				rig.signer.err = context.DeadlineExceeded
			}
			result, err := rig.service.Execute(test.ctx(), rig.command)
			if CodeOf(err) != test.code || result.ReleaseReference != nil || containsCall(rig.calls, "package.build") ||
				containsCall(rig.calls, "custody.completed") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}

func TestExportServiceCompletedReplayIsExactAndTamperEvident(t *testing.T) {
	rig := newExportRig(t)
	first, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil {
		t.Fatal(err)
	}
	rig.calls = nil
	second, err := rig.service.Execute(t.Context(), rig.command)
	if err != nil || !second.Replayed || second.ReleaseReference == nil ||
		*second.ReleaseReference != *first.ReleaseReference || second.Receipt.ReceiptDigest != first.Receipt.ReceiptDigest ||
		containsCall(rig.calls, "sign") || containsCall(rig.calls, "package.build") {
		t.Fatalf("calls=%v result=%+v err=%v", rig.calls, second, err)
	}

	changed := rig.command
	changed.DestinationDigest = pointerDigest("changed-destination")
	rig.calls = nil
	result, err := rig.service.Execute(t.Context(), changed)
	if CodeOf(err) != Denied || Reason(err) != string(ReasonChangedReplay) || result.ReleaseReference != nil {
		t.Fatalf("changed replay calls=%v result=%+v err=%v", rig.calls, result, err)
	}

	rig.packages.value.ManifestDigest = lifecycleDigest("tampered-manifest")
	rig.calls = nil
	result, err = rig.service.Execute(t.Context(), rig.command)
	if CodeOf(err) != Denied || Reason(err) != "export_replay_package_invalid" || result.ReleaseReference != nil {
		t.Fatalf("tampered replay calls=%v result=%+v err=%v", rig.calls, result, err)
	}
}
