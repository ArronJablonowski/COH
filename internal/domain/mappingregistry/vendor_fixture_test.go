package mappingregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type vendorCorpus struct {
	SchemaVersion string       `json:"schema_version"`
	Cases         []vendorCase `json:"cases"`
}

type vendorCase struct {
	Name             string `json:"name"`
	Envelope         string `json:"envelope"`
	Mutation         string `json:"mutation"`
	ExpectedCode     string `json:"expected_code"`
	ExpectedStatus   string `json:"expected_status"`
	ExpectedReason   string `json:"expected_reason"`
	ExpectedCoverage string `json:"expected_coverage"`
}

func TestExecutableVendorCorpus(t *testing.T) {
	corpusPath := "../../../contracts/mapping/v1/fixtures/vendor-corpus.json"
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var corpus vendorCorpus
	if err := decoder.Decode(&corpus); err != nil || corpus.SchemaVersion != "coh.mapping-vendor-corpus/v1" || len(corpus.Cases) == 0 || len(corpus.Cases) > 16 {
		t.Fatalf("corpus=%+v err=%v", corpus, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("corpus trailing content err=%v", err)
	}
	names := make(map[string]struct{}, len(corpus.Cases))
	for index, test := range corpus.Cases {
		if test.Name == "" {
			t.Fatal("corpus case has empty name")
		}
		if _, exists := names[test.Name]; exists {
			t.Fatalf("duplicate corpus case=%q", test.Name)
		}
		names[test.Name] = struct{}{}
		t.Run(test.Name, func(t *testing.T) {
			envelopePath := filepath.Clean(filepath.Join(filepath.Dir(corpusPath), test.Envelope))
			if envelopePath != "../../../contracts/normalization/v1/fixtures/valid/event.canonical.json" {
				t.Fatalf("unapproved envelope path=%q", envelopePath)
			}
			fixture := newServiceFixture(t)
			assertVendorEnvelope(t, envelopePath, fixture)
			fixture.command.OperationID = vendorOperationID(index)
			fixture.command.IdempotencyKey = digestBytes([]byte("vendor-corpus:" + test.Name))
			applyVendorMutation(t, fixture, test.Mutation)

			receipt, executeErr := fixture.execute(context.Background())
			if string(Code(executeErr)) != test.ExpectedCode || string(receipt.Status) != test.ExpectedStatus ||
				string(receipt.ReasonCode) != test.ExpectedReason {
				t.Fatalf("receipt=%+v err=%v", receipt, executeErr)
			}
			commits := fixture.store.committed()
			if len(commits) != 1 || commits[0].Outcome.Coverage != test.ExpectedCoverage {
				t.Fatalf("commits=%+v", commits)
			}
			if (receipt.Status == Applied && commits[0].NormalizedEnvelope == nil) ||
				(receipt.Status != Applied && commits[0].NormalizedEnvelope != nil) {
				t.Fatalf("status=%s envelope=%+v", receipt.Status, commits[0].NormalizedEnvelope)
			}
		})
	}
}

func assertVendorEnvelope(t *testing.T, path string, fixture *serviceFixture) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), fixture.input.input.CanonicalBytes()) {
		t.Fatal("service fixture does not execute the declared canonical vendor envelope")
	}
}

func applyVendorMutation(t *testing.T, fixture *serviceFixture, mutation string) {
	t.Helper()
	switch mutation {
	case "none":
		return
	case "remove-message-rule":
		removeApplicationRule(&fixture.input.selected.Signed.Manifest, "message")
		refreshServiceMapping(t, fixture)
	case "lossy-event-code":
		for index := range fixture.input.selected.Signed.Manifest.Rules {
			rule := &fixture.input.selected.Signed.Manifest.Rules[index]
			if rule.RuleID == "event-code" {
				rule.Operation, rule.OutputType = ToInteger, Integer
				rule.IntegerRange = &IntegerRange{Minimum: 0, Maximum: 999999}
				rule.Reversibility, rule.LossState, rule.LossReason = "not_reversible", "lossy", "type_narrowing"
			}
		}
		refreshServiceMapping(t, fixture)
	case "source-mismatch":
		fixture.command.Source.CollectionMethod = "substituted-method"
	case "registry-revoked":
		fixture.store.snapshots[0].CurrentRevoked = true
	case "signature-revoked":
		fixture.store.signatureRevoked = true
	default:
		t.Fatalf("unknown corpus mutation=%q", mutation)
	}
}

func refreshServiceMapping(t *testing.T, fixture *serviceFixture) {
	t.Helper()
	signed := &fixture.input.selected.Signed
	_, digest, err := CanonicalManifest(context.Background(), signed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	signed.ManifestDigest = digest
	fixture.input.selected.ManifestDigest = digest
	fixture.command.MappingDigest = digest
	fixture.store.mappings = map[string]SignedMapping{digest: cloneSignedMapping(*signed)}
	fixture.store.snapshots[0].CurrentManifestDigest = digest
}

func vendorOperationID(index int) string {
	const digits = "0123456789abcdef"
	return "0198e300-1000-7000-8000-00000000003" + string(digits[index])
}
