package deploymentprofile

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	testOrganizationID = "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e"
	testActorID        = "0198d6c4-1111-7111-8111-111111111111"
)

type auditRecorder struct {
	decisions []Decision
	err       error
}

func (recorder *auditRecorder) AppendProfileDecision(_ context.Context, decision Decision) error {
	if recorder.err != nil {
		return recorder.err
	}
	recorder.decisions = append(recorder.decisions, decision)
	return nil
}

func TestGuardBindsAuthorityLineageReplayAndAudit(t *testing.T) {
	recorder := &auditRecorder{}
	validator := Validator{Audit: recorder}
	config := workstation(Connected)
	authority := activeAuthority()
	first, err := validator.Validate(context.Background(), encode(t, config), authority)
	if err != nil || first.Outcome != "allowed" || first.Replayed || len(recorder.decisions) != 1 {
		t.Fatalf("first = %+v, audit = %+v, err = %v", first, recorder.decisions, err)
	}
	authority.CurrentRevision = 1
	authority.CurrentConfigDigest = first.ConfigDigest
	replayed, err := validator.Validate(context.Background(), encode(t, config), authority)
	if err != nil || !replayed.Replayed || replayed.ConfigDigest != first.ConfigDigest || len(recorder.decisions) != 2 {
		t.Fatalf("replay = %+v, audit = %+v, err = %v", replayed, recorder.decisions, err)
	}
	config.Change.Revision = 2
	config.Change.PreviousConfigDigest = first.ConfigDigest
	config.Connectivity.EndpointReferences[0] = "provider.secondary"
	next, err := validator.Validate(context.Background(), encode(t, config), authority)
	if err != nil || next.Replayed || next.ConfigDigest == first.ConfigDigest || len(recorder.decisions) != 3 {
		t.Fatalf("next = %+v, audit = %+v, err = %v", next, recorder.decisions, err)
	}
}

func TestGuardDeniesScopeRevocationStaleAndTamperedLineage(t *testing.T) {
	base := workstation(Connected)
	first, err := evaluate(context.Background(), encode(t, base))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		config    Config
		authority AuthoritySnapshot
		reason    string
	}{
		{"scope", base, AuthoritySnapshot{OrganizationID: "0198d6c4-2222-7222-8222-222222222222", ActorID: testActorID, Active: true}, "authority_scope_mismatch"},
		{"revoked", base, AuthoritySnapshot{OrganizationID: testOrganizationID, ActorID: testActorID, Active: false}, "actor_revoked"},
		{"stale", base, AuthoritySnapshot{OrganizationID: testOrganizationID, ActorID: testActorID, Active: true, CurrentRevision: 2, CurrentConfigDigest: testDigest}, "stale_revision"},
		{"lineage", revisionTwo(base, testDigest), AuthoritySnapshot{OrganizationID: testOrganizationID, ActorID: testActorID, Active: true, CurrentRevision: 1, CurrentConfigDigest: first.ConfigDigest}, "lineage_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &auditRecorder{}
			decision, validationErr := (Validator{Audit: recorder}).Validate(context.Background(), encode(t, test.config), test.authority)
			if Code(validationErr) != Denied || decision.ReasonCode != test.reason || decision.Outcome != "denied" || len(recorder.decisions) != 1 || recorder.decisions[0] != decision {
				t.Fatalf("decision = %+v, audit = %+v, err = %v", decision, recorder.decisions, validationErr)
			}
		})
	}
}

func TestGuardFailsClosedWhenAuditUnavailable(t *testing.T) {
	config := workstation(Connected)
	tests := []Validator{{}, {Audit: &auditRecorder{err: errors.New("private backend detail")}}}
	for _, validator := range tests {
		decision, err := validator.Validate(context.Background(), encode(t, config), activeAuthority())
		if Code(err) != Unavailable || decision.Outcome != "unavailable" || decision.ReasonCode != "audit_unavailable" || errors.Is(err, tests[1].Audit.(*auditRecorder).err) {
			t.Fatalf("decision = %+v, err = %v", decision, err)
		}
	}
}

func TestGuardCancellationTimeoutAndRecovery(t *testing.T) {
	recorder := &auditRecorder{}
	validator := Validator{Audit: recorder}
	input := encode(t, workstation(Connected))
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err := validator.Validate(canceled, input, activeAuthority())
	if Code(err) != Canceled || decision.Outcome != "canceled" || len(recorder.decisions) != 1 {
		t.Fatalf("canceled decision = %+v, audit = %+v, err = %v", decision, recorder.decisions, err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	decision, err = validator.Validate(expired, input, activeAuthority())
	if Code(err) != Timeout || decision.Outcome != "timeout" || len(recorder.decisions) != 2 {
		t.Fatalf("timeout decision = %+v, audit = %+v, err = %v", decision, recorder.decisions, err)
	}
	decision, err = validator.Validate(context.Background(), input, activeAuthority())
	if err != nil || decision.Outcome != "allowed" || len(recorder.decisions) != 3 {
		t.Fatalf("recovery decision = %+v, audit = %+v, err = %v", decision, recorder.decisions, err)
	}
}

func TestGuardAuditsInvalidAndDeniedInputs(t *testing.T) {
	recorder := &auditRecorder{}
	validator := Validator{Audit: recorder}
	if _, err := validator.Validate(context.Background(), []byte(`{"password":"do-not-echo"}`), activeAuthority()); Code(err) != InvalidInput {
		t.Fatal(err)
	}
	config := workstation(AirGapped)
	config.Connectivity.DNSAllowed = true
	if _, err := validator.Validate(context.Background(), encode(t, config), activeAuthority()); Code(err) != Denied {
		t.Fatal(err)
	}
	if len(recorder.decisions) != 2 || recorder.decisions[0].Outcome != "invalid" || recorder.decisions[1].Outcome != "denied" {
		t.Fatalf("audit decisions = %+v", recorder.decisions)
	}
}

func activeAuthority() AuthoritySnapshot {
	return AuthoritySnapshot{OrganizationID: testOrganizationID, ActorID: testActorID, Active: true}
}

func revisionTwo(config Config, previous string) Config {
	config.Change.Revision = 2
	config.Change.PreviousConfigDigest = previous
	return config
}
