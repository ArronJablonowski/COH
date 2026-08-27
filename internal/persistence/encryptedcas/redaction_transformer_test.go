package encryptedcas

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

func TestEncryptedCASRedactionTransformsTwicePublishesAndRetainsSource(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	store := newTestEncryptedStore(t, root, testWrappingKey("redaction"), now)
	sourceBytes := []byte("0123456789ABCDEFGHIJ")
	sourceObject := publishRedactionBytes(t, store, sourceBytes, "text/plain", "restricted", now)
	request, material := testDerivationRequest(t, sourceObject, sourceBytes, now)
	store.redactionRules = staticRedactionRules{material: material}

	derivation, stream, err := store.Derive(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("0156789***DE<R>HIJ")
	if derivation.DerivedArtifact.Digest != testCASDigest(want) || derivation.DerivedArtifact.Length != int64(len(want)) ||
		redaction.ValidateMapping(derivation.Mapping) != nil || len(derivation.Mapping.Entries) != 3 {
		t.Fatalf("derivation=%+v", derivation)
	}
	derivedBytes, err := readDerived(t.Context(), stream, 2)
	if err != nil || !bytes.Equal(derivedBytes, want) {
		t.Fatalf("derived=%q err=%v", derivedBytes, err)
	}
	derivedObject := publishDerivedStream(t, store, derivation.DerivedArtifact, &sliceSource{data: derivedBytes}, now)

	mappingBytes, err := redaction.CanonicalMapping(derivation.Mapping)
	if err != nil {
		t.Fatal(err)
	}
	mappingArtifact := domain.ArtifactRef{Digest: testCASDigest(mappingBytes),
		MediaType: "application/vnd.coh.redaction-mapping+json", Classification: "restricted", Length: int64(len(mappingBytes))}
	_ = publishDerivedStream(t, store, mappingArtifact, &sliceSource{data: mappingBytes}, now)

	resolvedSource, err := store.Resolve(t.Context(), publishedReference(sourceObject))
	if err != nil || resolvedSource.PlaintextDigest != request.Source.Artifact.Digest || len(objectFiles(t, root)) != 3 {
		t.Fatalf("source retention failed: %+v err=%v files=%v", resolvedSource, err, objectFiles(t, root))
	}
	if derivedObject.PlaintextDigest == sourceObject.PlaintextDigest {
		t.Fatal("derived aliased source")
	}
	for _, path := range objectFiles(t, root) {
		ciphertext, readErr := os.ReadFile(path)
		if readErr != nil || bytes.Contains(ciphertext, sourceBytes) || bytes.Contains(ciphertext, want) || bytes.Contains(ciphertext, mappingBytes) {
			t.Fatalf("plaintext appeared at rest in %s err=%v", path, readErr)
		}
	}
}

func TestEncryptedCASRedactionRejectsSegmentAndRuleMaterialDrift(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	sourceBytes := []byte("0123456789ABCDEFGHIJ")
	t.Run("segment", func(t *testing.T) {
		store := newTestEncryptedStore(t, t.TempDir(), testWrappingKey("segment"), now)
		object := publishRedactionBytes(t, store, sourceBytes, "text/plain", "restricted", now)
		request, material := testDerivationRequest(t, object, sourceBytes, now)
		request.Plan.Spans[1].SourceSegmentDigest = testCASDigest([]byte("changed"))
		request.Plan.MappingPlanDigest, _ = redaction.MappingPlanBindingDigest(request.Plan)
		request.Plan.PlanDigest, _ = redaction.PlanBindingDigest(request.Plan)
		store.redactionRules = staticRedactionRules{material: material}
		if _, _, err := store.Derive(t.Context(), request); CodeOf(err) != Denied || Reason(err) != "redaction_segment_digest_mismatch" {
			t.Fatalf("code=%s reason=%s err=%v", CodeOf(err), Reason(err), err)
		}
	})
	t.Run("material", func(t *testing.T) {
		store := newTestEncryptedStore(t, t.TempDir(), testWrappingKey("material"), now)
		object := publishRedactionBytes(t, store, sourceBytes, "text/plain", "restricted", now)
		request, material := testDerivationRequest(t, object, sourceBytes, now)
		material.Mask = []byte("!")
		store.redactionRules = staticRedactionRules{material: material}
		if _, _, err := store.Derive(t.Context(), request); CodeOf(err) != Denied || Reason(err) != "redaction_rule_material_invalid" {
			t.Fatalf("code=%s reason=%s err=%v", CodeOf(err), Reason(err), err)
		}
	})
	t.Run("invalid text output", func(t *testing.T) {
		invalid := append([]byte(nil), sourceBytes...)
		invalid[0] = 0xff
		store := newTestEncryptedStore(t, t.TempDir(), testWrappingKey("format"), now)
		object := publishRedactionBytes(t, store, invalid, "text/plain", "restricted", now)
		request, material := testDerivationRequest(t, object, invalid, now)
		store.redactionRules = staticRedactionRules{material: material}
		if _, _, err := store.Derive(t.Context(), request); CodeOf(err) != Denied || Reason(err) != "redaction_output_format_invalid" {
			t.Fatalf("code=%s reason=%s err=%v", CodeOf(err), Reason(err), err)
		}
	})
}

func TestEncryptedCASRedactionSecondPassReopensAndDetectsCiphertextDrift(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	store := newTestEncryptedStore(t, root, testWrappingKey("drift"), now)
	sourceBytes := []byte("0123456789ABCDEFGHIJ")
	object := publishRedactionBytes(t, store, sourceBytes, "text/plain", "restricted", now)
	request, material := testDerivationRequest(t, object, sourceBytes, now)
	store.redactionRules = staticRedactionRules{material: material}
	_, stream, err := store.Derive(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	path := objectFiles(t, root)[0]
	ciphertext, _ := os.ReadFile(path)
	ciphertext[len(ciphertext)/2] ^= 1
	if err = os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = readDerived(t.Context(), stream, 5); CodeOf(err) != Denied {
		t.Fatalf("code=%s err=%v", CodeOf(err), err)
	}
}

type staticRedactionRules struct{ material RedactionRuleMaterial }

func (rules staticRedactionRules) ResolveRedactionRule(context.Context, string) (RedactionRuleMaterial, bool, error) {
	return cloneRuleMaterial(rules.material), true, nil
}

func testDerivationRequest(t *testing.T, object evidenceingest.EncryptedObject, source []byte,
	now time.Time) (redaction.DerivationRequest, RedactionRuleMaterial) {
	t.Helper()
	mask, token := []byte("*"), []byte("<R>")
	maskDigest, tokenDigest := testCASDigest(mask), testCASDigest(token)
	rule := redaction.RuleSet{SchemaVersion: redaction.RuleSetSchemaVersion, ContractVersion: redaction.ContractVersion,
		RuleID: casUUID("redaction-rule"), Revision: 2, AllowedMediaTypes: []string{"text/plain"},
		PermittedModes: []redaction.ReplacementMode{redaction.Mask, redaction.Remove, redaction.Token},
		MaskDigest:     &maskDigest, TokenDigest: &tokenDigest, MaximumSpans: 8, MaximumSelectedBytes: 20,
		MaximumOutputBytes: 100, SignerKeyID: "redaction-signer", SignerKeyRevision: 3, Signature: strings.Repeat("A", 86)}
	rule.RuleDigest, _ = redaction.RuleBindingDigest(rule)
	reference := redaction.EvidenceReference{Artifact: domain.ArtifactRef{Digest: object.PlaintextDigest,
		MediaType: object.MediaType, Classification: object.Classification, Length: object.PlaintextLength},
		Manifest: domain.ArtifactRef{Digest: testCASDigest([]byte("manifest")), MediaType: "application/vnd.coh.artifact-manifest+json",
			Classification: object.Classification, Length: 512}, ManifestProvenanceDigest: testCASDigest([]byte("manifest-provenance")),
		IngestionReceiptDigest: testCASDigest([]byte("source-receipt"))}
	plan := redaction.ApprovedPlan{SchemaVersion: redaction.PlanSchemaVersion, ContractVersion: redaction.ContractVersion,
		PlanID: casUUID("redaction-plan"), Case: object.Case, Source: reference, RuleID: rule.RuleID, RuleRevision: rule.Revision,
		RuleDigest: rule.RuleDigest, ReasonDigest: testCASDigest([]byte("reason")), Spans: []redaction.PlanSpan{
			{Ordinal: 1, SourceStart: 2, SourceEnd: 5, SourceSegmentDigest: testCASDigest(source[2:5]), ReplacementMode: redaction.Remove, ExpectedOutputStart: 2, ExpectedOutputEnd: 2},
			{Ordinal: 2, SourceStart: 10, SourceEnd: 13, SourceSegmentDigest: testCASDigest(source[10:13]), ReplacementMode: redaction.Mask, ExpectedOutputStart: 7, ExpectedOutputEnd: 10},
			{Ordinal: 3, SourceStart: 15, SourceEnd: 17, SourceSegmentDigest: testCASDigest(source[15:17]), ReplacementMode: redaction.Token, ExpectedOutputStart: 12, ExpectedOutputEnd: 15}},
		OutputMediaType: "text/plain", OutputClassification: "confidential", MaximumOutputBytes: 100,
		ApprovalID: casUUID("approval"), ApprovalFingerprintDigest: testCASDigest([]byte("fingerprint")),
		ApprovalManifestDigest: testCASDigest([]byte("approval-manifest")), PolicyDecisionDigest: testCASDigest([]byte("policy-decision")),
		PolicyDigest: testCASDigest([]byte("policy")), ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	plan.MappingPlanDigest, _ = redaction.MappingPlanBindingDigest(plan)
	plan.PlanDigest, _ = redaction.PlanBindingDigest(plan)
	verified := redaction.VerifiedSource{Reference: reference, SourceIdentityDigest: testCASDigest([]byte("identity")),
		VerificationDigest: testCASDigest([]byte("verification"))}
	request := redaction.DerivationRequest{Case: object.Case, Source: reference, Verified: verified, Rule: rule, Plan: plan,
		CreatedAt: now, PreviousProvenanceDigest: reference.ManifestProvenanceDigest, Deadline: now.Add(30 * time.Minute)}
	return request, RedactionRuleMaterial{RuleDigest: rule.RuleDigest, Mask: mask, Token: token}
}

func publishRedactionBytes(t *testing.T, store *Store, value []byte, mediaType, classification string,
	now time.Time) evidenceingest.EncryptedObject {
	t.Helper()
	request := stageRequest(t, value, now)
	request.MediaType, request.Classification = mediaType, classification
	request.EncryptionContextDigest, _ = evidenceingest.EncryptionContextBindingDigest(request)
	staged, err := store.Stage(t.Context(), request, &sliceSource{data: value})
	if err != nil {
		t.Fatal(err)
	}
	published, _, err := store.Publish(t.Context(), staged)
	if err != nil {
		t.Fatal(err)
	}
	return published
}

func publishDerivedStream(t *testing.T, store *Store, artifact domain.ArtifactRef, source evidenceingest.Source,
	now time.Time) evidenceingest.EncryptedObject {
	t.Helper()
	request := stageRequest(t, []byte("placeholder"), now)
	request.ExpectedDigest, request.ExpectedLength = artifact.Digest, artifact.Length
	request.MediaType, request.Classification = artifact.MediaType, artifact.Classification
	request.EncryptionContextDigest, _ = evidenceingest.EncryptionContextBindingDigest(request)
	staged, err := store.Stage(t.Context(), request, source)
	if err != nil {
		t.Fatal(err)
	}
	published, _, err := store.Publish(t.Context(), staged)
	if err != nil {
		t.Fatal(err)
	}
	return published
}

func readDerived(ctx context.Context, source redaction.DerivedSource, chunk int) ([]byte, error) {
	var output bytes.Buffer
	buffer := make([]byte, chunk)
	for {
		count, err := source.ReadContext(ctx, buffer)
		output.Write(buffer[:count])
		if err != nil {
			if err == io.EOF {
				return output.Bytes(), nil
			}
			return output.Bytes(), err
		}
	}
}
