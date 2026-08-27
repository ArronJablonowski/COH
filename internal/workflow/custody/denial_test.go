package custody

import (
	"context"
	"testing"
	"time"
)

func TestControllerAuditsApprovalRevocationCrossScopeAndStaleDenials(t *testing.T) {
	tests := map[string]func(Command, *custodyTestAuthority, *custodyTestCases, *custodyTestEvidence){
		"approval": func(_ Command, authority *custodyTestAuthority, _ *custodyTestCases, _ *custodyTestEvidence) {
			authority.deny, authority.denyReason = true, ReasonApprovalRequired
		},
		"revocation": func(_ Command, authority *custodyTestAuthority, _ *custodyTestCases, _ *custodyTestEvidence) {
			authority.deny, authority.denyReason = true, ReasonRevoked
		},
		"stale actor": func(_ Command, authority *custodyTestAuthority, _ *custodyTestCases, _ *custodyTestEvidence) {
			authority.deny, authority.denyReason = true, ReasonStaleActor
		},
		"stale artifact": func(_ Command, authority *custodyTestAuthority, _ *custodyTestCases, _ *custodyTestEvidence) {
			authority.deny, authority.denyReason = true, ReasonArtifactInvalid
		},
		"cross scope": func(command Command, _ *custodyTestAuthority, _ *custodyTestCases,
			evidence *custodyTestEvidence) {
			value := evidence.values[evidenceKey(command.Subject)]
			value.Reference.Artifact.Digest = fixtureDigest("cross.scope.artifact")
			evidence.values[evidenceKey(command.Subject)] = value
		},
		"stale case": func(_ Command, _ *custodyTestAuthority, cases *custodyTestCases, _ *custodyTestEvidence) {
			cases.current.Revision++
		},
	}
	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			controller, command, authority, cases, evidence, ledger, auditor := custodyControllerFixture(t)
			configure(command, authority, cases, evidence)
			if _, err := controller.Execute(context.Background(), command); err == nil {
				t.Fatal("denial returned success")
			}
			if len(ledger.records) != 0 || len(auditor.events) != 1 || auditor.events[0].Outcome != "denied" ||
				auditor.events[0].SubjectDigest != command.Subject.Artifact.Digest {
				t.Fatal("denial was not recorded once with safe artifact identity")
			}
			if name == "approval" && auditor.events[0].ReasonCode != "approval_required" ||
				name == "revocation" && auditor.events[0].ReasonCode != "revoked" ||
				name == "stale actor" && auditor.events[0].ReasonCode != "stale_actor" ||
				name == "stale artifact" && auditor.events[0].ReasonCode != "artifact_invalid" {
				t.Fatalf("denial reason=%s", auditor.events[0].ReasonCode)
			}
		})
	}
}

func TestControllerAuditsExpiredCommandWithoutProtectedDependencyCalls(t *testing.T) {
	controller, command, authority, _, evidence, ledger, auditor := custodyControllerFixture(t)
	command.Deadline = custodyFixtureTime.Add(-time.Second)
	if _, err := controller.Execute(context.Background(), command); CodeOf(err) != InvalidInput {
		t.Fatalf("expired command error=%v", err)
	}
	if len(authority.requests) != 0 || evidence.resolve != 0 || len(ledger.records) != 0 ||
		len(auditor.events) != 1 || auditor.events[0].ReasonCode != "invalid_input" {
		t.Fatal("expired command did not stop early with one safe audit")
	}
}

func TestControllerAuditsCancellationAndTimeoutWithoutCustodyMutation(t *testing.T) {
	for _, test := range []struct {
		name string
		ctx  func() context.Context
		want string
	}{
		{"canceled", func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, "request_canceled"},
		{"timeout", func() context.Context {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			cancel()
			return ctx
		}, "request_timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, command, authority, _, evidence, ledger, auditor := custodyControllerFixture(t)
			if _, err := controller.Execute(test.ctx(), command); err == nil {
				t.Fatal("canceled operation returned success")
			}
			if len(ledger.records) != 0 || len(authority.requests) != 0 || evidence.resolve != 0 ||
				len(auditor.events) != 1 || auditor.events[0].ReasonCode != test.want {
				t.Fatal("cancellation/timeout did not fail closed with one safe audit")
			}
		})
	}
}

func TestControllerDetectsTamperedReplayAndAuditsTheDenial(t *testing.T) {
	controller, command, _, _, _, ledger, auditor := custodyControllerFixture(t)
	if _, err := controller.Execute(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	ledger.records[0].ChainHash = fixtureDigest("tampered.chain")
	if _, err := controller.Execute(context.Background(), command); CodeOf(err) != Denied {
		t.Fatalf("tampered replay error=%v", err)
	}
	if len(ledger.records) != 1 || len(auditor.events) != 2 || auditor.events[1].Outcome != "denied" {
		t.Fatal("tampered replay was not denied and audited without another custody append")
	}
}

func TestDenialAuditFailureCannotBecomeUsableDenialOrSuccess(t *testing.T) {
	controller, command, authority, _, _, ledger, auditor := custodyControllerFixture(t)
	authority.deny, authority.denyReason, auditor.fail = true, ReasonRevoked, true
	if _, err := controller.Execute(context.Background(), command); CodeOf(err) != Unavailable {
		t.Fatalf("audit failure error=%v", err)
	}
	if len(ledger.records) != 0 || len(auditor.events) != 0 {
		t.Fatal("failed denial audit mutated custody or appeared durable")
	}
}
