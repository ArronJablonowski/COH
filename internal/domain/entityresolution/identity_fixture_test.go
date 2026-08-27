package entityresolution

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type identityMethodFixture struct {
	CaseMatch struct {
		Algorithm           string   `json:"algorithm"`
		DomainSeparatorUTF8 string   `json:"domain_separator_utf8"`
		Input               []string `json:"input"`
		KeyExportable       bool     `json:"key_exportable"`
		KeyScope            string   `json:"key_scope"`
	} `json:"case_match"`
	Catalog map[string][]struct {
		IdentifierType string `json:"identifier_type"`
		Normalization  string `json:"normalization"`
	} `json:"catalog"`
	ContractVersion string `json:"contract_version"`
	MethodVersion   string `json:"method_version"`
	SchemaVersion   string `json:"schema_version"`
}

func TestIdentityMethodFixtureIsCanonicalPinnedAndExecutable(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/entity/v1/fixtures/identity-method-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil || !bytes.Equal(input, append(canonical, '\n')) {
		t.Fatalf("fixture is not canonical: %v", err)
	}
	if digest := digestBytes(canonical); digest != "sha256:2ba2c987ef57b7edc98650985727890fe69224be794a7a1095375fe4d052132c" {
		t.Fatalf("fixture digest=%s", digest)
	}
	var fixture identityMethodFixture
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "coh.entity-identity-method/v1" || fixture.ContractVersion != ContractVersion ||
		fixture.MethodVersion != MethodVersion || fixture.CaseMatch.Algorithm != "HMAC-SHA-256" ||
		fixture.CaseMatch.DomainSeparatorUTF8 != "COH-ENTITY-MATCH-V1\x00" || fixture.CaseMatch.KeyScope != "case" ||
		fixture.CaseMatch.KeyExportable || len(fixture.CaseMatch.Input) != 2 ||
		!bytes.Equal([]byte(fixture.CaseMatch.Input[0]), []byte("identifier_type")) ||
		!bytes.Equal([]byte(fixture.CaseMatch.Input[1]), []byte("canonical_identifier")) {
		t.Fatalf("fixture=%+v", fixture)
	}
	count := 0
	for role, pairs := range fixture.Catalog {
		for _, pair := range pairs {
			count++
			binding := IdentifierBinding{Role: role, IdentifierType: pair.IdentifierType, Normalization: pair.Normalization,
				MatchDigest: testDigest("identity-fixture"), DerivationKeyRevision: 1}
			if !validIdentifier(binding) {
				t.Fatalf("catalog pair rejected: %+v", binding)
			}
			binding.IdentifierType = "unknown"
			if validIdentifier(binding) {
				t.Fatalf("unknown type accepted: %+v", binding)
			}
		}
	}
	if count != 9 {
		t.Fatalf("catalog pairs=%d", count)
	}
}
