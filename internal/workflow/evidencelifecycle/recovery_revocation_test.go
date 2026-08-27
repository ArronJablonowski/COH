package evidencelifecycle

import (
	"errors"
	"testing"
)

func TestFreshRevocationStopsEveryRestartRecovery(t *testing.T) {
	revoke := func(value *Decision) { value.Outcome, value.ReasonCode = Deny, ReasonRevoked }
	t.Run("export", func(t *testing.T) {
		rig := newExportRig(t)
		rig.custody.failPhase = Completed
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil ||
			rig.store.progress.Phase != Packaged {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.custody.failPhase, rig.authority.mutate, rig.calls = "", revoke, nil
		rig.service = restartExportService(t, rig)
		result, err := rig.service.Execute(t.Context(), rig.command)
		if CodeOf(err) != Denied || result.ReleaseReference != nil ||
			containsCall(rig.calls, "package.proof.recover") || containsCall(rig.calls, "custody.completed") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
	t.Run("import", func(t *testing.T) {
		rig := newImportRig(t)
		rig.custody.failPhase = Completed
		if _, err := rig.service.Execute(t.Context(), rig.command, "quarantine.import.1"); err == nil ||
			rig.store.progress.Phase != Published {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.custody.failPhase, rig.authority.mutate, rig.calls = "", revoke, nil
		service, err := NewImportService(rig.authority, rig.cases, rig.custody, rig.reader, rig.publisher,
			rig.store, rig.auditor, rig.service.clock)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Execute(t.Context(), rig.command, "quarantine.import.1")
		if CodeOf(err) != Denied || len(result.Imported) != 0 || containsCall(rig.calls, "publish") ||
			containsCall(rig.calls, "custody.completed") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
	t.Run("hold", func(t *testing.T) {
		rig := newHoldRig(t, PlaceHold)
		rig.custody.failPhase = Completed
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil ||
			rig.store.progress.Phase != CaseRecorded {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.custody.failPhase, rig.authority.mutate, rig.calls = "", revoke, nil
		service, err := NewHoldService(rig.authority, rig.cases, rig.lifecycle, rig.service.evidence,
			rig.custody, rig.store, rig.auditor, rig.service.clock)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Execute(t.Context(), rig.command)
		if CodeOf(err) != Denied || result.Receipt.ReceiptDigest != "" ||
			containsCall(rig.calls, "case.resolve") || containsCall(rig.calls, "custody.completed") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		rig := newDeleteRig(t)
		rig.disposer.err = errors.New("disposition unavailable")
		if _, err := rig.service.Execute(t.Context(), rig.command); err == nil ||
			rig.store.progress.Phase != Tombstoned {
			t.Fatalf("err=%v phase=%s", err, rig.store.progress.Phase)
		}
		rig.disposer.err, rig.authority.mutate, rig.calls = nil, revoke, nil
		service, err := NewDeleteService(rig.authority, rig.cases, rig.lifecycle, rig.service.evidence,
			rig.custody, rig.disposer, rig.store, rig.auditor, rig.service.clock)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Execute(t.Context(), rig.command)
		if CodeOf(err) != Denied || result.Receipt.ReceiptDigest != "" ||
			containsCall(rig.calls, "disposition.recover") || containsCall(rig.calls, "dispose") {
			t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
		}
	})
}
