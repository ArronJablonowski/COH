package opaengine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/policy"
)

const allowPolicy = `package coh.authz

default decision := {"allow": false, "reason_code": "policy_denied", "approval_required": false}

decision := {"allow": true, "reason_code": "policy_allowed", "approval_required": true} if {
	input.schema_version == "coh.policy-input/v1"
	input.manifest.action_tier == "T2"
	input.manifest.operation == "publish_draft"
	input.actor.permissions[_] == "action.request"
	input.runtime.validator_state == "qualified"
}
`

type fixedClock struct{ now time.Time }

func (clock *fixedClock) Now() time.Time { return clock.now }

type auditMemory struct {
	mu     sync.Mutex
	events []policy.AuditEvent
	fail   bool
}

func (memory *auditMemory) AppendPolicyEvent(_ context.Context, event policy.AuditEvent) error {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if memory.fail {
		return os.ErrPermission
	}
	encoded, _ := json.Marshal(event)
	var clone policy.AuditEvent
	_ = json.Unmarshal(encoded, &clone)
	memory.events = append(memory.events, clone)
	return nil
}

type bundleKey struct {
	privateKey ed25519.PrivateKey
	authority  policy.BundleAuthority
}

func newBundleKey(t *testing.T, revision uint64) bundleKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return bundleKey{
		privateKey: privateKey,
		authority: policy.BundleAuthority{KeyID: "policy.primary", KeyRevision: revision,
			Algorithm: SignatureAlgorithm, Active: true, PublicKey: publicKey},
	}
}

func signedBundle(t *testing.T, revision uint64, key bundleKey, source string) []byte {
	t.Helper()
	bundle := policyBundle{
		bundleMetadata: bundleMetadata{
			SchemaVersion: BundleSchemaVersion, ContractVersion: BundleContractVersion,
			BundleID: uuid(strconv.FormatUint(revision%16, 16)), OrganizationID: uuid("1"), TenantID: uuid("3"),
			PolicyRevision: revision, Entrypoint: DecisionEntrypoint,
			ValidFrom: "2026-08-25T22:00:00.000000000Z", ValidUntil: "2026-08-30T22:00:00.000000000Z",
		},
		Modules: []bundleModule{{Path: "coh/authz.rego", Source: source}},
		Data:    map[string]any{},
	}
	return signPolicyBundle(t, bundle, key)
}

func signPolicyBundle(t *testing.T, bundle policyBundle, key bundleKey) []byte {
	t.Helper()
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBundle, err := domaincontract.Canonicalize(bundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	envelope := signedBundleEnvelope{
		SchemaVersion: EnvelopeSchemaVersion, ContractVersion: BundleContractVersion,
		Bundle: bundle, BundleDigest: digestBytes(canonicalBundle), SignerKeyID: key.authority.KeyID,
		SignerKeyRevision: key.authority.KeyRevision, SignatureAlgorithm: SignatureAlgorithm,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key.privateKey, signatureMessage(canonicalBundle))),
	}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	canonicalEnvelope, err := domaincontract.Canonicalize(envelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	return canonicalEnvelope
}

func validRequest(t *testing.T, policyDigest string, policyRevision uint64) policy.Request {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "action", "v1", "fixtures", "valid", "detection-publish.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest actionmanifest.Manifest
	if err := json.Unmarshal(fixture, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.PolicyDigest, manifest.PolicyRevision = policyDigest, policyRevision
	manifest.ValidFrom, manifest.ValidUntil = "2026-08-25T23:00:00.000000000Z", "2026-08-26T00:00:00.000000000Z"
	manifestBytes, _ := json.Marshal(manifest)
	validated, err := actionmanifest.Decode(context.Background(), manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("COH-CYB-47-INERT-ACTION-KEY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	authority := actionmanifest.SignerAuthority{ActorID: manifest.RequestorActorID, KeyID: "requestor.primary",
		KeyRevision: 4, Active: true, PublicKey: privateKey.Public().(ed25519.PublicKey)}
	message := append([]byte(actionmanifest.SignatureDomain), validated.CanonicalBytes()...)
	envelope := actionmanifest.Envelope{SchemaVersion: actionmanifest.EnvelopeSchemaVersion,
		ContractVersion: actionmanifest.ContractVersion, Manifest: manifest, ManifestDigest: validated.Digest,
		SignerActorID: authority.ActorID, SignerKeyRevision: authority.KeyRevision, KeyID: authority.KeyID,
		SignatureAlgorithm: "ed25519", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}
	envelopeBytes, _ := json.Marshal(envelope)
	verified, err := actionmanifest.Verify(context.Background(), envelopeBytes, authority)
	if err != nil {
		t.Fatal(err)
	}
	return policy.Request{EvaluationID: uuid("8"), Phase: policy.IntentCreated, Manifest: verified,
		Actor: policy.ActorAuthority{ActorID: manifest.RequestorActorID, OrganizationID: manifest.OrganizationID,
			TenantID: manifest.TenantID, CaseID: manifest.CaseID, Revision: 4, Active: true,
			Roles: []string{"analyst"}, Permissions: []string{"action.request"}},
		Runtime: policy.RuntimeAuthority{DataRoute: "connector.elastic", ValidatorState: "qualified",
			ToolRegistered: true, TargetsAuthorized: true, TenantAuthorized: true, DataRouteAuthorized: true,
			CapabilityFieldsKnown: true},
	}
}

func committedBundle(t *testing.T) ([]byte, policy.BundleAuthority) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "contracts", "policy", "v1", "fixtures", "valid")
	contents, err := os.ReadFile(filepath.Join(root, "signed-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := os.ReadFile(filepath.Join(root, "policy-primary.public-key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(string(encodedKey)))
	if err != nil {
		t.Fatal(err)
	}
	return contents, policy.BundleAuthority{KeyID: "policy.primary", KeyRevision: 3, Algorithm: SignatureAlgorithm,
		Active: true, PublicKey: ed25519.PublicKey(publicKey)}
}

func uuid(fill string) string {
	return "0198d6c4-" + fill + fill + fill + fill + "-7" + fill + fill + fill + "-8" + fill + fill + fill + "-" +
		fill + fill + fill + fill + fill + fill + fill + fill + fill + fill + fill + fill
}
