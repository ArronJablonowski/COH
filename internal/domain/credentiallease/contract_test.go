package credentiallease

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const credentialFixtureRoot = "../../../contracts/credential/v1/fixtures"

func TestFrozenValidIssuanceFixture(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(credentialFixtureRoot, "valid", "*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("valid fixture inventory = %d, err = %v", len(paths), err)
	}
	input, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeIssuanceRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	first, err := RequestDigest(request)
	second, secondErr := RequestDigest(request)
	if err != nil || secondErr != nil || first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("digests = %q, %q; errors = %v, %v", first, second, err, secondErr)
	}
}

type denialCorpus struct {
	Schema          string       `json:"schema"`
	ContractVersion string       `json:"contract_version"`
	Cases           []denialCase `json:"cases"`
}

type denialCase struct {
	Name      string          `json:"name"`
	Operation string          `json:"operation"`
	Path      string          `json:"path"`
	Value     json.RawMessage `json:"value,omitempty"`
	Reason    string          `json:"reason"`
}

func TestFrozenIssuanceDenialCorpus(t *testing.T) {
	input, err := os.ReadFile(filepath.Join(credentialFixtureRoot, "denial-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus denialCorpus
	if err := json.Unmarshal(input, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "coh.credential-lease-denials/v1" || corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 24 {
		t.Fatalf("denial corpus identity or inventory is invalid: %+v", corpus)
	}
	base, err := os.ReadFile(filepath.Join(credentialFixtureRoot, "valid", "connector.request.json"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if test.Name == "" || seen[test.Name] {
				t.Fatalf("missing or duplicate case name %q", test.Name)
			}
			seen[test.Name] = true
			_, decodeErr := DecodeIssuanceRequest(mutateDocument(t, base, test.Operation, test.Path, test.Value))
			if Code(decodeErr) != InvalidInput && Code(decodeErr) != Denied {
				t.Fatalf("code = %q, err = %v", Code(decodeErr), decodeErr)
			}
			if errorReason(decodeErr) != test.Reason {
				t.Fatalf("reason = %q, want %q, err = %v", errorReason(decodeErr), test.Reason, decodeErr)
			}
		})
	}
}

func TestIssuanceContractContainsNoCapabilityOrSecretValue(t *testing.T) {
	encoded, err := json.Marshal(IssuanceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret_value", "password", "lease_token", "capability", "private_key"} {
		if strings.Contains(strings.ToLower(string(encoded)), `"`+forbidden+`"`) {
			t.Fatalf("issuance contract exposes forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func mutateDocument(t *testing.T, input []byte, operation, pointer string, rawValue json.RawMessage) []byte {
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
	switch operation {
	case "remove":
		delete(current, key)
	case "set":
		var value any
		if err := json.Unmarshal(rawValue, &value); err != nil {
			t.Fatal(err)
		}
		current[key] = value
	default:
		t.Fatalf("unknown mutation operation %q", operation)
	}
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}
