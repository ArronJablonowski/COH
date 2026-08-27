package evidencelifecycle

import (
	"context"
	"testing"
	"time"
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
		ctx  func() (context.Context, context.CancelFunc)
		code ErrorCode
	}{
		{"canceled", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx, func() {}
		}, Canceled},
		{"timeout", func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		}, Timeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newExportRig(t)
			ctx, cancel := test.ctx()
			defer cancel()
			rig.signer.err = context.Canceled
			if test.code == Timeout {
				rig.signer.err = context.DeadlineExceeded
			}
			result, err := rig.service.Execute(ctx, rig.command)
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

func TestExportServiceRestartsFromEveryDurablePhase(t *testing.T) {
	for _, test := range []struct {
		name      string
		phase     Phase
		fail      func(*exportRig)
		clear     func(*exportRig)
		forbidden []string
		required  string
	}{
		{"planned", Planned, func(rig *exportRig) { rig.custody.failPhase = Authorized },
			func(rig *exportRig) { rig.custody.failPhase = "" }, nil, "custody.authorized"},
		{"authorized", Authorized, func(rig *exportRig) { rig.signer.err = context.Canceled },
			func(rig *exportRig) { rig.signer.err = nil }, []string{"custody.authorized"}, "package.build"},
		{"packaged", Packaged, func(rig *exportRig) { rig.custody.failPhase = Completed },
			func(rig *exportRig) { rig.custody.failPhase = "" },
			[]string{"custody.authorized", "sign", "package.build"}, "package.proof.recover"},
		{"custodied", Custodied, func(rig *exportRig) { rig.lifecycle.err = context.Canceled },
			func(rig *exportRig) { rig.lifecycle.err = nil },
			[]string{"custody.authorized", "sign", "package.build", "custody.completed"}, "case.export"},
		{"case recorded", CaseRecorded, func(rig *exportRig) { rig.auditor.appendErr = context.Canceled },
			func(rig *exportRig) { rig.auditor.appendErr = nil },
			[]string{"custody.authorized", "sign", "package.build", "custody.completed", "case.export"},
			"package.proof.recover"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rig := newExportRig(t)
			test.fail(rig)
			if result, err := rig.service.Execute(t.Context(), rig.command); err == nil ||
				result.ReleaseReference != nil || rig.store.progress.Phase != test.phase {
				t.Fatalf("first calls=%v result=%+v err=%v phase=%s", rig.calls, result, err,
					rig.store.progress.Phase)
			}
			test.clear(rig)
			rig.calls = nil
			rig.service = restartExportService(t, rig)
			result, err := rig.service.Execute(t.Context(), rig.command)
			if err != nil || result.ReleaseReference == nil || ValidateReceipt(result.Receipt) != nil ||
				!containsCall(rig.calls, test.required) {
				t.Fatalf("restart calls=%v result=%+v err=%v", rig.calls, result, err)
			}
			for _, forbidden := range test.forbidden {
				if containsCall(rig.calls, forbidden) {
					t.Fatalf("restart repeated %s: %v", forbidden, rig.calls)
				}
			}
		})
	}
}

func restartExportService(t *testing.T, rig *exportRig) *ExportService {
	t.Helper()
	service, err := NewExportService(rig.authority, rig.cases, rig.lifecycle, rig.service.evidence,
		rig.service.redactions, rig.custody, rig.signer, rig.verifier, rig.packages, rig.store, rig.auditor,
		rig.service.clock, rig.service.signing)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestExportServiceRestartRejectsInterveningCustodyAndCaseChanges(t *testing.T) {
	t.Run("custody", func(t *testing.T) {
		rig := newExportRig(t)
		rig.signer.err = context.Canceled
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil ||
			rig.store.progress.Phase != Authorized {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		last := lifecycleTestNow
		rig.custody.head = CustodyHead{Case: rig.command.Case, Sequence: rig.custody.head.Sequence + 1,
			ChainHash: lifecycleDigest("intervening-custody"), LastRecordAt: &last}
		rig.custody.rememberHead(rig.custody.head)
		rig.signer.err, rig.calls = nil, nil
		rig.service = restartExportService(t, rig)
		result, err := rig.service.Execute(t.Context(), rig.command)
		if CodeOf(err) != Conflict || Reason(err) != string(ReasonStaleCustody) ||
			result.ReleaseReference != nil || containsCall(rig.calls, "package.build") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
	t.Run("case", func(t *testing.T) {
		rig := newExportRig(t)
		rig.auditor.appendErr = context.Canceled
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil ||
			rig.store.progress.Phase != CaseRecorded {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.cases.snapshot.Revision++
		rig.cases.snapshot.ProvenanceDigest = lifecycleDigest("intervening-case-change")
		rig.auditor.appendErr, rig.calls = nil, nil
		rig.service = restartExportService(t, rig)
		result, err := rig.service.Execute(t.Context(), rig.command)
		if CodeOf(err) != Denied || Reason(err) != "export_case_recovery_invalid" ||
			result.ReleaseReference != nil || containsCall(rig.calls, "store.commit") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
}
