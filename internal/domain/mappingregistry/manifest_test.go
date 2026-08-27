package mappingregistry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestCanonicalManifestAndSignaturePreimage(t *testing.T) {
	manifest := validManifest()
	canonical, digest, err := CanonicalManifest(context.Background(), manifest)
	if err != nil {
		t.Fatalf("CanonicalManifest() err=%v", err)
	}
	again, againDigest, err := CanonicalManifest(context.Background(), manifest)
	if err != nil || !bytes.Equal(again, canonical) || againDigest != digest {
		t.Fatalf("second canonicalization digest=%q err=%v", againDigest, err)
	}
	if got := digestBytes(canonical); got != digest {
		t.Fatalf("digestBytes(canonical)=%q want %q", got, digest)
	}
	if want := "sha256:e0188ba18a567eaf1ff58caa57fa511ec4ba0f52e1cafa85b77ad9940506c0ca"; digest != want {
		t.Fatalf("canonical manifest digest=%q want %q", digest, want)
	}
	preimage, err := SignaturePreimage(digest)
	if err != nil {
		t.Fatalf("SignaturePreimage() err=%v", err)
	}
	if len(preimage) != len(signatureDomain)+32 || !bytes.Equal(preimage[:len(signatureDomain)], []byte(signatureDomain)) {
		t.Fatalf("SignaturePreimage() length=%d domain=%q", len(preimage), preimage[:len(signatureDomain)])
	}
	if _, err := SignaturePreimage("sha256:not-a-digest"); Code(err) != InvalidInput || ErrorReason(err) != ManifestDigestMismatch {
		t.Fatalf("invalid digest err=%v code=%q reason=%q", err, Code(err), ErrorReason(err))
	}
}

func TestDecodeSignedMappingStrictAndDigestBound(t *testing.T) {
	signed := validSignedMapping(t)
	encoded, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, canonical, digest, err := DecodeSignedMapping(context.Background(), encoded)
	if err != nil {
		t.Fatalf("DecodeSignedMapping() err=%v", err)
	}
	if decoded.ManifestDigest != signed.ManifestDigest || digest != digestBytes(canonical) {
		t.Fatalf("decoded manifest=%q envelope=%q", decoded.ManifestDigest, digest)
	}

	duplicate := bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"schema_version":"duplicate","schema_version":`), 1)
	unknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unexpected":true}`)...)
	mutated := signed
	mutated.Manifest.Name = "changed.mapping"
	mutation, err := json.Marshal(mutated)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{"duplicate": duplicate, "unknown": unknown, "mutation": mutation} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := DecodeSignedMapping(context.Background(), input); Code(err) != InvalidInput {
				t.Fatalf("DecodeSignedMapping() err=%v code=%q", err, Code(err))
			}
		})
	}
}

func TestSignedMappingRejectsEnvelopeBindingDrift(t *testing.T) {
	tests := map[string]func(*SignedMapping){
		"publisher": func(value *SignedMapping) {
			value.PublisherID = "018f47de-16b2-7a40-8c91-9f04d02b1531"
		},
		"key revision": func(value *SignedMapping) { value.PublisherKeyRevision = 0 },
		"algorithm":    func(value *SignedMapping) { value.SignatureAlgorithm = "rsa" },
		"signature":    func(value *SignedMapping) { value.Signature = "not-ed25519" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			signed := validSignedMapping(t)
			mutate(&signed)
			if _, _, err := CanonicalSignedMapping(context.Background(), signed); Code(err) != InvalidInput || ErrorReason(err) != SignatureInvalid {
				t.Fatalf("CanonicalSignedMapping() err=%v code=%q reason=%q", err, Code(err), ErrorReason(err))
			}
		})
	}
}

func TestManifestRejectsInvalidRuleBindings(t *testing.T) {
	tests := map[string]func(*Manifest){
		"sequence gap": func(value *Manifest) { value.Rules[0].Sequence = 2 },
		"output collision": func(value *Manifest) {
			second := value.Rules[0]
			second.RuleID = "host-child"
			second.Sequence = 2
			second.OutputPath = value.Rules[0].OutputPath + ".child"
			value.Rules = append(value.Rules, second)
		},
		"ignored mapped input": func(value *Manifest) {
			value.IgnoredFields = []IgnoredField{{Path: *value.Rules[0].InputPath, Reason: "reserved"}}
		},
		"noncanonical absent constant": func(value *Manifest) {
			value.Rules[0].ConstantValue = json.RawMessage(`{}`)
		},
		"null ignored fields": func(value *Manifest) { value.IgnoredFields = nil },
		"null enum table":     func(value *Manifest) { value.Rules[0].EnumTable = nil },
		"lossy reversible": func(value *Manifest) {
			value.Rules[0].LossState = "lossy"
			value.Rules[0].LossReason = "declared_vendor_loss"
		},
		"mismatched entity hint": func(value *Manifest) {
			value.Rules[0].EntityHint.IdentifierType = "sha256"
		},
		"missing predecessor":    func(value *Manifest) { value.Revision = 2 },
		"unbound product digest": func(value *Manifest) { value.Source.ProductDigest = testDigest },
		"nonbijective reversible enum": func(value *Manifest) {
			input := "original.event.kind"
			value.Rules[0] = Rule{
				RuleID: "event-kind", Sequence: 1, Operation: Enum, InputPath: &input,
				OutputNamespace: "ocsf", OutputPath: "ocsf.activity_name", InputType: String, OutputType: String,
				Required: true, ConstantValue: json.RawMessage(`null`),
				EnumTable: []EnumEntry{
					{Source: json.RawMessage(`"login"`), Target: json.RawMessage(`"logon"`)},
					{Source: json.RawMessage(`"signin"`), Target: json.RawMessage(`"logon"`)},
				},
				Reversibility: "reversible", LossState: "lossless", LossReason: "none",
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validManifest()
			mutate(&manifest)
			if _, _, err := CanonicalManifest(context.Background(), manifest); err == nil {
				t.Fatal("CanonicalManifest() accepted invalid manifest")
			}
		})
	}
}

func TestManifestAcceptsTypedNullConstant(t *testing.T) {
	manifest := validManifest()
	manifest.Rules[0] = Rule{
		RuleID: "null-value", Sequence: 1, Operation: Constant,
		OutputNamespace: "ocsf", OutputPath: "ocsf.unmapped", InputType: Null, OutputType: Null,
		ConstantValue: json.RawMessage(`null`), EnumTable: []EnumEntry{},
		Reversibility: "not_reversible", LossState: "lossless", LossReason: "constant",
	}
	if _, _, err := CanonicalManifest(context.Background(), manifest); err != nil {
		t.Fatalf("CanonicalManifest(null constant) err=%v", err)
	}
}

func TestCanonicalManifestContextAndRecovery(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := CanonicalManifest(canceled, validManifest()); Code(err) != CanceledError || ErrorReason(err) != ContextCanceled || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err=%v code=%q reason=%q", err, Code(err), ErrorReason(err))
	}
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	if _, _, err := CanonicalManifest(deadline, validManifest()); Code(err) != TimeoutError || ErrorReason(err) != ContextDeadline || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline err=%v code=%q reason=%q", err, Code(err), ErrorReason(err))
	}
	invalid := validManifest()
	invalid.SchemaVersion = "wrong"
	if _, _, err := CanonicalManifest(context.Background(), invalid); err == nil {
		t.Fatal("invalid manifest unexpectedly accepted")
	}
	if _, _, err := CanonicalManifest(context.Background(), validManifest()); err != nil {
		t.Fatalf("recovery canonicalization err=%v", err)
	}
}

func validSignedMapping(t *testing.T) SignedMapping {
	t.Helper()
	manifest := validManifest()
	_, digest, err := CanonicalManifest(context.Background(), manifest)
	if err != nil {
		t.Fatalf("CanonicalManifest() err=%v", err)
	}
	return SignedMapping{
		SchemaVersion: SignedSchemaVersion, ContractVersion: ContractVersion,
		Manifest: manifest, ManifestDigest: digest, PublisherID: manifest.IssuerID,
		PublisherKeyID: "mapping-publisher-1", PublisherKeyRevision: 1,
		SignatureAlgorithm: "ed25519", Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}
}

func validManifest() Manifest {
	inputPath := "original.host.name"
	product := "acme.sensor"
	return Manifest{
		SchemaVersion: ManifestSchemaVersion, ContractVersion: ContractVersion,
		MappingID: "018f47de-16b2-7a40-8c91-9f04d02b1528", Name: "acme.sensor.base", Version: "1.0.0", Revision: 1,
		Source: SourceMatcher{
			SourceKind: "connector", Product: product, ProductDigest: digestBytes([]byte(product)), SourceSchema: "acme.event",
			SourceSchemaVersion: "2026-08", SourceSchemaDigest: testDigest, CollectionMethod: "api", CollectionMethodVersion: "v1",
		},
		Compatibility: Compatibility{TargetManifestDigest, "coh.normalized-event-envelope/v1", OCSFVersion, OCSFCommit, ECSVersion, ECSCommit},
		Rules: []Rule{{
			RuleID: "host-name", Sequence: 1, Operation: Copy, InputPath: &inputPath,
			OutputNamespace: "ocsf", OutputPath: "ocsf.device.name", InputType: String, OutputType: String,
			Required: true, ConstantValue: json.RawMessage(`null`), EnumTable: []EnumEntry{},
			Reversibility: "reversible", LossState: "lossless", LossReason: "none",
			EntityHint: &EntityHint{Role: "host.name", IdentifierType: "hostname", Normalization: "lowercase_ascii", ConfidenceCeilingMillionths: 900_000},
		}},
		IgnoredFields:  []IgnoredField{{Path: "original.vendor.display", Reason: "nonsemantic_display"}},
		UnmappedPolicy: "deny", Limits: Limits{MaxRules: 8, MaxInputLeaves: 64, MaxOutputLeaves: 64, MaxValueBytes: 4096, MaxDepth: 16},
		IssuerID: "018f47de-16b2-7a40-8c91-9f04d02b1529", ReviewDigest: testDigest,
		CreatedAt: "2026-08-27T00:00:00.000000000Z", NotBefore: "2026-08-27T00:00:00.000000000Z", NotAfter: "2027-08-27T00:00:00.000000000Z",
		Revocation: RevocationBinding{ListID: "018f47de-16b2-7a40-8c91-9f04d02b1530", ListDigest: testDigest, MinimumRevision: 1},
	}
}
