package evidencelifecycle

import (
	"context"
	"testing"
	"time"
)

func TestHoldAndDeleteRejectCancellationAndTimeoutBeforeStateAccess(t *testing.T) {
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
		t.Run("hold/"+test.name, func(t *testing.T) {
			rig := newHoldRig(t, PlaceHold)
			ctx, cancel := test.ctx()
			defer cancel()
			result, err := rig.service.Execute(ctx, rig.command)
			if CodeOf(err) != test.code || result.Receipt.ReceiptDigest != "" ||
				containsCall(rig.calls, "recover") || containsCall(rig.calls, "case.place_hold") ||
				containsCall(rig.calls, "custody.completed") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
		t.Run("delete/"+test.name, func(t *testing.T) {
			rig := newDeleteRig(t)
			ctx, cancel := test.ctx()
			defer cancel()
			result, err := rig.service.Execute(ctx, rig.command)
			if CodeOf(err) != test.code || result.Receipt.ReceiptDigest != "" ||
				containsCall(rig.calls, "recover") || containsCall(rig.calls, "case.delete") ||
				containsCall(rig.calls, "dispose") {
				t.Fatalf("calls=%v result=%+v err=%v", rig.calls, result, err)
			}
		})
	}
}
