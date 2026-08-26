package approvalfingerprint

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/policy"
)

type fixedClock struct{ now time.Time }

func (clock *fixedClock) Now() time.Time { return clock.now }

type auditMemory struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   bool
}

func (audit *auditMemory) AppendApprovalFingerprintEvent(_ context.Context, event AuditEvent) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.fail {
		return os.ErrPermission
	}
	audit.events = append(audit.events, event)
	return nil
}

func TestFrozenFingerprintBuildVerifyAndAudit(t *testing.T) {
	verified, decision, expected := frozenInputs(t)
	audit := &auditMemory{}
	engine, err := New(audit, testClock())
	if err != nil {
		t.Fatal(err)
	}
	authority := authorityFor(verified)
	built, err := engine.Build(t.Context(), verified, authority, decision)
	if err != nil || !reflect.DeepEqual(built, expected) {
		t.Fatalf("built = %+v, expected = %+v, err = %v", built, expected, err)
	}
	verifiedResult, err := engine.Verify(t.Context(), expected, verified, authority, decision)
	if err != nil || !reflect.DeepEqual(verifiedResult, expected) {
		t.Fatalf("verified = %+v, err = %v", verifiedResult, err)
	}
	again, err := engine.Build(t.Context(), verified, authority, decision)
	if err != nil || again.FingerprintDigest != expected.FingerprintDigest {
		t.Fatalf("stable build = %+v, err = %v", again, err)
	}
	if len(audit.events) != 3 || audit.events[0].ReasonCode != "fingerprint_built" ||
		audit.events[1].ReasonCode != "fingerprint_verified" {
		t.Fatalf("audit events = %+v", audit.events)
	}
}

func TestEveryApprovalSensitiveManifestChangeInvalidates(t *testing.T) {
	verified, decision, original := frozenInputs(t)
	base := verified.Manifest()
	otherUUID := "0198d6c4-9999-7999-8999-999999999999"
	changedDigest := "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	tests := []struct {
		name   string
		mutate func(*actionmanifest.Manifest)
	}{
		{"organization", func(value *actionmanifest.Manifest) { value.OrganizationID = otherUUID }},
		{"tenant", func(value *actionmanifest.Manifest) { value.TenantID = otherUUID }},
		{"case", func(value *actionmanifest.Manifest) { value.CaseID = otherUUID }},
		{"owner", func(value *actionmanifest.Manifest) { value.ActionOwnerActorID = otherUUID }},
		{"target", func(value *actionmanifest.Manifest) { value.TargetDigests[0] = changedDigest }},
		{"argument", func(value *actionmanifest.Manifest) { value.ArgumentsDigest = changedDigest }},
		{"payload", func(value *actionmanifest.Manifest) { value.PayloadDigest = changedDigest }},
		{"credential", func(value *actionmanifest.Manifest) { value.CredentialReferenceDigest = &changedDigest }},
		{"tool", func(value *actionmanifest.Manifest) { value.Tool.Digest = changedDigest }},
		{"policy", func(value *actionmanifest.Manifest) { value.PolicyDigest = changedDigest }},
		{"roe", func(value *actionmanifest.Manifest) { value.ROEDigest = &changedDigest }},
		{"validity", func(value *actionmanifest.Manifest) { value.ValidUntil = "2026-08-25T23:59:00.000000000Z" }},
		{"use-count", func(value *actionmanifest.Manifest) { value.MaximumUseCount = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneManifest(base)
			test.mutate(&changed)
			changedVerified := signManifest(t, changed)
			changedDecision := bindDecision(t, decision, changedVerified)
			engine, _ := New(&auditMemory{}, testClock())
			authority := authorityFor(changedVerified)
			built, err := engine.Build(t.Context(), changedVerified, authority, changedDecision)
			if err != nil || built.FingerprintDigest == original.FingerprintDigest {
				t.Fatalf("built = %+v, err = %v", built, err)
			}
			if _, err := engine.Verify(t.Context(), original, changedVerified, authority, changedDecision); policy.Reason(err) != "fingerprint_mismatch" {
				t.Fatalf("verify err = %v", err)
			}
		})
	}
}

func TestPolicyDecisionDenials(t *testing.T) {
	verified, decision, _ := frozenInputs(t)
	tests := []struct {
		name   string
		reason string
		mutate func(*policy.Decision)
		final  bool
	}{
		{"digest", "policy_decision_digest", func(value *policy.Decision) {
			value.DecisionDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, false},
		{"outcome", "policy_not_allowed", func(value *policy.Decision) { value.Outcome = "denied" }, true},
		{"phase", "policy_phase", func(value *policy.Decision) { value.Phase = policy.PreDispatch }, true},
		{"approval", "approval_not_required", func(value *policy.Decision) { value.ApprovalRequired = false }, true},
		{"manifest", "manifest_binding", func(value *policy.Decision) {
			value.ManifestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, true},
		{"policy", "policy_binding", func(value *policy.Decision) { value.PolicyRevision++ }, true},
		{"actor", "actor_binding", func(value *policy.Decision) {
			value.ActorID = "0198d6c4-9999-7999-8999-999999999999"
		}, true},
		{"future", "policy_time", func(value *policy.Decision) {
			value.EvaluatedAt = "2026-08-25T23:31:00.000000000Z"
		}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := decision
			test.mutate(&changed)
			if test.final {
				var err error
				changed, err = policy.FinalizeDecision(changed)
				if err != nil {
					t.Fatal(err)
				}
			}
			engine, _ := New(&auditMemory{}, testClock())
			if _, err := engine.Build(t.Context(), verified, authorityFor(verified), changed); policy.Reason(err) != test.reason {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestPolicyDecisionByteChangesInvalidate(t *testing.T) {
	verified, decision, original := frozenInputs(t)
	tests := []struct {
		name   string
		mutate func(*policy.Decision)
	}{
		{"actor-revision", func(value *policy.Decision) { value.ActorRevision++ }},
		{"evaluation-id", func(value *policy.Decision) {
			value.EvaluationID = "0198d6c4-9999-7999-8999-999999999999"
		}},
		{"evaluation-time", func(value *policy.Decision) {
			value.EvaluatedAt = "2026-08-25T23:29:00.000000000Z"
		}},
		{"bundle", func(value *policy.Decision) {
			value.BundleID = "0198d6c4-9999-7999-8999-999999999999"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := decision
			test.mutate(&changed)
			changed, err := policy.FinalizeDecision(changed)
			if err != nil {
				t.Fatal(err)
			}
			engine, _ := New(&auditMemory{}, testClock())
			authority := authorityFor(verified)
			built, err := engine.Build(t.Context(), verified, authority, changed)
			if err != nil || built.FingerprintDigest == original.FingerprintDigest {
				t.Fatalf("built = %+v, err = %v", built, err)
			}
			if _, err := engine.Verify(t.Context(), original, verified, authority, changed); policy.Reason(err) != "fingerprint_mismatch" {
				t.Fatalf("verify err = %v", err)
			}
		})
	}
}

func TestCancellationTimeoutAuditFailureAndRecovery(t *testing.T) {
	verified, decision, expected := frozenInputs(t)
	audit := &auditMemory{}
	engine, _ := New(audit, testClock())
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	authority := authorityFor(verified)
	revoked := authority
	revoked.Active = false
	if _, err := engine.Build(t.Context(), verified, revoked, decision); policy.Reason(err) != "manifest_authority" {
		t.Fatalf("revoked signer err = %v", err)
	}
	if _, err := engine.Build(canceled, verified, authority, decision); policy.Code(err) != policy.Canceled {
		t.Fatalf("canceled err = %v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := engine.Verify(expired, expected, verified, authority, decision); policy.Code(err) != policy.Timeout {
		t.Fatalf("timeout err = %v", err)
	}
	audit.fail = true
	if _, err := engine.Build(t.Context(), verified, authority, decision); policy.Reason(err) != "audit_unavailable" {
		t.Fatalf("audit err = %v", err)
	}
	audit.fail = false
	if built, err := engine.Build(t.Context(), verified, authority, decision); err != nil ||
		built.FingerprintDigest != expected.FingerprintDigest {
		t.Fatalf("recovery = %+v, err = %v", built, err)
	}
}

func TestExpiredManifestAndConcurrentDeterminism(t *testing.T) {
	verified, decision, expected := frozenInputs(t)
	expiredManifest := cloneManifest(verified.Manifest())
	expiredManifest.ValidUntil = "2026-08-25T23:29:00.000000000Z"
	expiredVerified := signManifest(t, expiredManifest)
	expiredDecision := bindDecision(t, decision, expiredVerified)
	expiredDecision.EvaluatedAt = "2026-08-25T23:28:00.000000000Z"
	expiredDecision, _ = policy.FinalizeDecision(expiredDecision)
	engine, _ := New(&auditMemory{}, testClock())
	if _, err := engine.Build(t.Context(), expiredVerified, authorityFor(expiredVerified), expiredDecision); policy.Reason(err) != "manifest_not_current" {
		t.Fatalf("expired err = %v", err)
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 16)
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			built, err := engine.Build(context.Background(), verified, authorityFor(verified), decision)
			if err == nil && built.FingerprintDigest != expected.FingerprintDigest {
				err = errors.New("fingerprint drift")
			}
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func frozenInputs(t *testing.T) (actionmanifest.VerifiedEnvelope, policy.Decision, Fingerprint) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "contracts")
	actionBytes, err := os.ReadFile(filepath.Join(root, "action", "v1", "fixtures", "valid", "detection-publish.signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := deterministicKey()
	var action actionmanifest.Envelope
	if err := json.Unmarshal(actionBytes, &action); err != nil {
		t.Fatal(err)
	}
	authority := actionmanifest.SignerAuthority{ActorID: action.SignerActorID, KeyID: action.KeyID,
		KeyRevision: action.SignerKeyRevision, Active: true, PublicKey: publicKey}
	verified, err := actionmanifest.Verify(t.Context(), actionBytes, authority)
	if err != nil {
		t.Fatal(err)
	}
	var decision policy.Decision
	readJSON(t, filepath.Join(root, "approval", "v1", "fixtures", "valid", "policy-decision.json"), &decision)
	var expected Fingerprint
	readJSON(t, filepath.Join(root, "approval", "v1", "fixtures", "valid", "approval-fingerprint.json"), &expected)
	return verified, decision, expected
}

func signManifest(t *testing.T, manifest actionmanifest.Manifest) actionmanifest.VerifiedEnvelope {
	t.Helper()
	encoded, _ := json.Marshal(manifest)
	validated, err := actionmanifest.Decode(t.Context(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := deterministicKey()
	message := append([]byte(actionmanifest.SignatureDomain), validated.CanonicalBytes()...)
	envelope := actionmanifest.Envelope{SchemaVersion: actionmanifest.EnvelopeSchemaVersion,
		ContractVersion: actionmanifest.ContractVersion, Manifest: validated.Value(), ManifestDigest: validated.Digest,
		SignerActorID: manifest.RequestorActorID, SignerKeyRevision: 4, KeyID: "requestor.primary",
		SignatureAlgorithm: "ed25519", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}
	envelopeBytes, _ := json.Marshal(envelope)
	canonical, _ := domaincontract.Canonicalize(envelopeBytes)
	authority := actionmanifest.SignerAuthority{ActorID: manifest.RequestorActorID, KeyID: "requestor.primary",
		KeyRevision: 4, Active: true, PublicKey: publicKey}
	verified, err := actionmanifest.Verify(t.Context(), canonical, authority)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func bindDecision(t *testing.T, decision policy.Decision, verified actionmanifest.VerifiedEnvelope) policy.Decision {
	t.Helper()
	manifest := verified.Manifest()
	decision.ManifestDigest, decision.PolicyDigest = verified.ManifestDigest, manifest.PolicyDigest
	decision.PolicyRevision, decision.ActorID = manifest.PolicyRevision, manifest.RequestorActorID
	finalized, err := policy.FinalizeDecision(decision)
	if err != nil {
		t.Fatal(err)
	}
	return finalized
}

func cloneManifest(value actionmanifest.Manifest) actionmanifest.Manifest {
	encoded, _ := json.Marshal(value)
	var cloned actionmanifest.Manifest
	_ = json.Unmarshal(encoded, &cloned)
	return cloned
}

func deterministicKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("COH-CYB-52-INERT-TEST-KEY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func authorityFor(verified actionmanifest.VerifiedEnvelope) actionmanifest.SignerAuthority {
	publicKey, _ := deterministicKey()
	return actionmanifest.SignerAuthority{ActorID: verified.SignerActorID, KeyID: verified.KeyID,
		KeyRevision: verified.SignerKeyRevision, Active: true, PublicKey: publicKey}
}

func readJSON(t *testing.T, path string, output any) {
	t.Helper()
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(input, output); err != nil {
		t.Fatal(err)
	}
}

func testClock() *fixedClock {
	return &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)}
}
