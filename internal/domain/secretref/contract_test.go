package secretref

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secretFixtureRoot = "../../../contracts/secret/v1/fixtures"

func TestFrozenValidSecretReferenceFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(secretFixtureRoot, "valid", "*.json"))
	if err != nil || len(paths) != 4 {
		t.Fatalf("valid fixture inventory = %d, err = %v", len(paths), err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			input, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.HasSuffix(path, ".reference.json") {
				reference, decodeErr := DecodeReference(input)
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				first, digestErr := ReferenceDigest(reference)
				second, secondErr := ReferenceDigest(reference)
				if digestErr != nil || secondErr != nil || first != second || !strings.HasPrefix(first, "sha256:") {
					t.Fatalf("digests = %q, %q; errors = %v, %v", first, second, digestErr, secondErr)
				}
				return
			}
			request, decodeErr := DecodeResolutionRequest(input)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if _, digestErr := ReferenceDigest(request.Reference); digestErr != nil {
				t.Fatal(digestErr)
			}
		})
	}
}

type denialCorpus struct {
	Schema          string       `json:"schema"`
	ContractVersion string       `json:"contract_version"`
	Cases           []denialCase `json:"cases"`
}

type denialCase struct {
	Name         string          `json:"name"`
	Document     string          `json:"document"`
	Base         string          `json:"base"`
	Operation    string          `json:"operation"`
	Path         string          `json:"path"`
	Value        json.RawMessage `json:"value,omitempty"`
	ExpectedCode ErrorCode       `json:"expected_code"`
	Reason       string          `json:"reason"`
}

func TestFrozenSecretReferenceDenialCorpus(t *testing.T) {
	input, err := os.ReadFile(filepath.Join(secretFixtureRoot, "denial-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus denialCorpus
	if err := json.Unmarshal(input, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "coh.secret-reference-denials/v1" || corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 18 {
		t.Fatalf("denial corpus identity or inventory is invalid: %+v", corpus)
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if test.Name == "" || seen[test.Name] {
				t.Fatalf("missing or duplicate case name %q", test.Name)
			}
			seen[test.Name] = true
			base, readErr := os.ReadFile(filepath.Join(secretFixtureRoot, "valid", test.Base))
			if readErr != nil {
				t.Fatal(readErr)
			}
			mutated := mutateDocument(t, base, test.Operation, test.Path, test.Value)
			var validationErr error
			switch test.Document {
			case "reference":
				_, validationErr = DecodeReference(mutated)
			case "request":
				_, validationErr = DecodeResolutionRequest(mutated)
			default:
				t.Fatalf("unknown document type %q", test.Document)
			}
			if Code(validationErr) != test.ExpectedCode || errorReason(validationErr) != test.Reason {
				t.Fatalf("code = %q, reason = %q, err = %v", Code(validationErr), errorReason(validationErr), validationErr)
			}
		})
	}
}

func TestSecretReferenceTypesHaveNoSecretValueField(t *testing.T) {
	encoded, err := json.Marshal(ResolutionRequest{
		Reference: Reference{Backend: "protected-file", EntryID: "entry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret_value", "password", "token", "path", "url", "command", "environment"} {
		if strings.Contains(strings.ToLower(string(encoded)), `"`+forbidden+`"`) {
			t.Fatalf("resolution contract exposes forbidden field %q: %s", forbidden, encoded)
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
