package oidcidentity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

const oidcFixtureRoot = "../../../contracts/identity/oidc/v1/fixtures"

func TestFrozenValidOIDCFixtures(t *testing.T) {
	provider, err := os.ReadFile(filepath.Join(oidcFixtureRoot, "valid", "native-server.provider.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProviderConfig(provider); err != nil {
		t.Fatal(err)
	}
	claims, err := os.ReadFile(filepath.Join(oidcFixtureRoot, "valid", "analyst.claims.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeClaims(claims); err != nil {
		t.Fatal(err)
	}
}

type denialCorpus struct {
	Schema          string       `json:"schema"`
	ContractVersion string       `json:"contract_version"`
	Cases           []denialCase `json:"cases"`
}

type denialCase struct {
	Name      string          `json:"name"`
	Document  string          `json:"document"`
	Operation string          `json:"operation"`
	Path      string          `json:"path"`
	Value     json.RawMessage `json:"value,omitempty"`
	Reason    string          `json:"reason"`
}

func TestFrozenOIDCDenialCorpus(t *testing.T) {
	input, err := os.ReadFile(filepath.Join(oidcFixtureRoot, "denial-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus denialCorpus
	if err := json.Unmarshal(input, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "coh.server-oidc-denials/v1" || corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 24 {
		t.Fatalf("denial corpus identity or inventory invalid: %+v", corpus)
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if test.Name == "" || seen[test.Name] {
				t.Fatalf("missing or duplicate name %q", test.Name)
			}
			seen[test.Name] = true
			baseName := "native-server.provider.json"
			if test.Document == "claims" {
				baseName = "analyst.claims.json"
			} else if test.Document != "provider" {
				t.Fatalf("unknown document %q", test.Document)
			}
			base, readErr := os.ReadFile(filepath.Join(oidcFixtureRoot, "valid", baseName))
			if readErr != nil {
				t.Fatal(readErr)
			}
			mutated := mutateOIDCDocument(t, base, test.Operation, test.Path, test.Value)
			var decodeErr error
			if test.Document == "provider" {
				_, decodeErr = DecodeProviderConfig(mutated)
			} else {
				_, decodeErr = DecodeClaims(mutated)
			}
			if Code(decodeErr) != localidentity.InvalidInput || errorReason(decodeErr) != test.Reason {
				t.Fatalf("code = %q, reason = %q, want %q, err = %v", Code(decodeErr), errorReason(decodeErr), test.Reason, decodeErr)
			}
		})
	}
}

func TestOIDCContractHasNoBearerOrKeyField(t *testing.T) {
	for _, value := range []any{ProviderConfig{}, Claims{}} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"access_token", "id_token", "client_secret", "private_key", "session_token", "signing_key"} {
			if strings.Contains(strings.ToLower(string(encoded)), `"`+forbidden+`"`) {
				t.Fatalf("contract exposes %q: %s", forbidden, encoded)
			}
		}
	}
}

func TestStrictDecoderRejectsDuplicateClaim(t *testing.T) {
	input := []byte(`{"iss":"https://one.invalid","iss":"https://two.invalid"}`)
	_, err := DecodeClaims(input)
	if Code(err) != localidentity.InvalidInput || errorReason(err) != "claims_decoding" {
		t.Fatalf("err = %v", err)
	}
}

func mutateOIDCDocument(t *testing.T, input []byte, operation, pointer string, rawValue json.RawMessage) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(input, &document); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	current := document
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			t.Fatalf("mutation path %q is not an object path", pointer)
		}
		current = next
	}
	key := parts[len(parts)-1]
	if operation == "remove" {
		delete(current, key)
	} else if operation == "set" {
		var value any
		if err := json.Unmarshal(rawValue, &value); err != nil {
			t.Fatal(err)
		}
		current[key] = value
	} else {
		t.Fatalf("unknown operation %q", operation)
	}
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}
