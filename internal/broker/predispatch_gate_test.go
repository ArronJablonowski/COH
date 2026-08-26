package broker

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
)

func TestPreDispatchT2ThroughT4SuccessAndMandatoryOrder(t *testing.T) {
	for _, tier := range []string{"T2", "T3", "T4"} {
		t.Run(tier, func(t *testing.T) {
			fixture := newPreDispatchFixture(t, tier)
			authority, err := fixture.gate.authorize(context.Background(), fixture.command)
			if err != nil {
				t.Fatal(err)
			}
			expectedOrder := []string{"policy", "approval", "audit"}
			if tier == "T4" {
				expectedOrder = []string{"policy", "roe", "approval", "audit"}
			}
			if !reflect.DeepEqual(*fixture.order, expectedOrder) {
				t.Fatalf("order = %v, want %v", *fixture.order, expectedOrder)
			}
			if authority.Manifest.ManifestDigest != fixture.verified.ManifestDigest ||
				authority.PreDispatchDecision.Phase != policy.PreDispatch || authority.Approval.UseCount != 1 ||
				authority.AuditEventID == "" || len(fixture.audit.events) != 1 {
				t.Fatalf("authority = %+v audit=%d", authority, len(fixture.audit.events))
			}
			if tier == "T4" && (authority.ROE == nil || authority.ROE.Digest != *fixture.manifest.ROEDigest ||
				len(authority.Approval.Grants) != 2) {
				t.Fatalf("T4 authority = %+v", authority)
			}
			if tier != "T4" && authority.ROE != nil {
				t.Fatalf("unexpected ROE proof: %+v", authority.ROE)
			}
			event := fixture.audit.events[0]
			if event.Outcome != "allowed" || event.ReasonCode != "predispatch_authorized" ||
				event.SubjectDigest != fixture.verified.ManifestDigest || event.EventID != authority.AuditEventID {
				t.Fatalf("audit event = %+v", event)
			}
		})
	}
}

func TestPreDispatchDeniesManifestPolicyIdentityAndScopeChanges(t *testing.T) {
	t.Run("one-byte manifest", func(t *testing.T) {
		fixture := newPreDispatchFixture(t, "T2")
		fixture.command.SignedManifest = append([]byte(nil), fixture.command.SignedManifest...)
		for index := len(fixture.command.SignedManifest) - 2; index >= 0; index-- {
			if fixture.command.SignedManifest[index] >= 'A' && fixture.command.SignedManifest[index] <= 'z' {
				fixture.command.SignedManifest[index] ^= 1
				break
			}
		}
		if _, err := fixture.gate.authorize(context.Background(), fixture.command); lifecycle.Reason(err) != "manifest_authority" {
			t.Fatalf("err = %v", err)
		}
		if len(*fixture.order) != 0 {
			t.Fatalf("downstream calls = %v", *fixture.order)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*preDispatchFixture)
		reason string
	}{
		{"stale policy decision", func(f *preDispatchFixture) {
			f.policy.mutate = func(value *policy.Decision) {
				value.EvaluatedAt = testTime.Add(-time.Nanosecond).Format(timestampLayout)
			}
		}, "policy_decision_stale"},
		{"replaced policy", func(f *preDispatchFixture) {
			f.policy.err = policy.NewError(policy.Denied, "policy_state_stale")
		}, "policy_state_stale"},
		{"revoked actor", func(f *preDispatchFixture) { f.command.PolicyActor.Active = false }, "actor_revoked"},
		{"stale actor revision", func(f *preDispatchFixture) { f.command.PolicyActor.Revision-- }, "identity_state_stale"},
		{"scope expansion", func(f *preDispatchFixture) { f.command.PolicyActor.TenantID = secondApproverID }, "actor_scope_mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPreDispatchFixture(t, "T2")
			test.mutate(fixture)
			if _, err := fixture.gate.authorize(context.Background(), fixture.command); lifecycle.Reason(err) != test.reason {
				t.Fatalf("err = %v, want %s", err, test.reason)
			}
			if slices.Contains(*fixture.order, "approval") || slices.Contains(*fixture.order, "audit") {
				t.Fatalf("downstream calls = %v", *fixture.order)
			}
		})
	}
}

func TestPreDispatchT4RequiresROEAndTwoFreshDistinctApprovers(t *testing.T) {
	t.Run("invalid ROE scope", func(t *testing.T) {
		fixture := newPreDispatchFixture(t, "T4")
		fixture.roe.mutate = func(proof *verifiedROEProof) { proof.TenantID = secondApproverID }
		if _, err := fixture.gate.authorize(context.Background(), fixture.command); lifecycle.Reason(err) != "roe_authority" {
			t.Fatalf("err = %v", err)
		}
		if !reflect.DeepEqual(*fixture.order, []string{"policy", "roe"}) {
			t.Fatalf("order = %v", *fixture.order)
		}
	})

	t.Run("only one approver", func(t *testing.T) {
		fixture := newPreDispatchFixtureState(t, "T4", false)
		if _, err := fixture.gate.authorize(context.Background(), fixture.command); lifecycle.Reason(err) != "approval_not_current" {
			t.Fatalf("err = %v", err)
		}
		if slices.Contains(*fixture.order, "audit") {
			t.Fatalf("audit reservation unexpectedly allowed: %v", *fixture.order)
		}
	})

	t.Run("principal collision", func(t *testing.T) {
		fixture := newPreDispatchFixture(t, "T4")
		fixture.command.Approval.GrantAuthorities[1].Principal.PrincipalID = approverPrincipalID
		if _, err := fixture.gate.authorize(context.Background(), fixture.command); lifecycle.Reason(err) != "approver_authority_changed" {
			t.Fatalf("err = %v", err)
		}
		if slices.Contains(*fixture.order, "audit") {
			t.Fatalf("audit reservation unexpectedly allowed: %v", *fixture.order)
		}
	})
}

func TestPreDispatchReplayAuditFailureCancellationAndTimeoutReturnNoAuthority(t *testing.T) {
	t.Run("approval replay", func(t *testing.T) {
		fixture := newPreDispatchFixture(t, "T2")
		if _, err := fixture.gate.authorize(context.Background(), fixture.command); err != nil {
			t.Fatal(err)
		}
		*fixture.order = nil
		authority, err := fixture.gate.authorize(context.Background(), fixture.command)
		if lifecycle.Reason(err) != "approval_replayed" || authority.AuditEventID != "" {
			t.Fatalf("authority=%+v err=%v", authority, err)
		}
		if !reflect.DeepEqual(*fixture.order, []string{"policy", "approval", "audit"}) ||
			fixture.audit.events[len(fixture.audit.events)-1].Outcome != "denied" {
			t.Fatalf("order=%v events=%+v", *fixture.order, fixture.audit.events)
		}
	})

	t.Run("audit unavailable consumes approval", func(t *testing.T) {
		fixture := newPreDispatchFixture(t, "T2")
		fixture.audit.fail = true
		authority, err := fixture.gate.authorize(context.Background(), fixture.command)
		if lifecycle.Reason(err) != "audit_unavailable" || authority.AuditEventID != "" {
			t.Fatalf("authority=%+v err=%v", authority, err)
		}
		fixture.audit.fail = false
		*fixture.order = nil
		if _, err := fixture.gate.authorize(context.Background(), fixture.command); lifecycle.Reason(err) != "approval_replayed" {
			t.Fatalf("retry err=%v", err)
		}
	})

	t.Run("canceled after consume", func(t *testing.T) {
		fixture := newPreDispatchFixture(t, "T2")
		ctx, cancel := context.WithCancel(context.Background())
		fixture.consumer.cancel = cancel
		authority, err := fixture.gate.authorize(ctx, fixture.command)
		if lifecycle.Code(err) != lifecycle.Canceled || authority.AuditEventID != "" {
			t.Fatalf("authority=%+v err=%v", authority, err)
		}
		if len(fixture.audit.events) != 1 || fixture.audit.events[0].Outcome != "canceled" {
			t.Fatalf("events=%+v", fixture.audit.events)
		}
	})

	for _, test := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		code lifecycle.ErrorCode
	}{
		{"canceled before verify", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		}, lifecycle.Canceled},
		{"timed out before verify", func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}, lifecycle.Timeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPreDispatchFixture(t, "T2")
			ctx, cancel := test.ctx()
			defer cancel()
			authority, err := fixture.gate.authorize(ctx, fixture.command)
			if lifecycle.Code(err) != test.code || authority.AuditEventID != "" || len(*fixture.order) != 0 {
				t.Fatalf("authority=%+v order=%v err=%v", authority, *fixture.order, err)
			}
		})
	}
}
