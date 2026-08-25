package deploymentprofile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureRoot = "../../../contracts/deployment/v1/fixtures"

func TestFrozenValidFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(fixtureRoot, "valid", "*.json"))
	if err != nil || len(paths) != 5 {
		t.Fatalf("valid fixture inventory = %d, err = %v", len(paths), err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			input, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			decision, validationErr := evaluate(context.Background(), input)
			if validationErr != nil || decision.Outcome != "allowed" {
				t.Fatalf("decision = %+v, err = %v", decision, validationErr)
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
	Base         string          `json:"base"`
	Path         string          `json:"path"`
	Value        json.RawMessage `json:"value"`
	ExpectedCode ErrorCode       `json:"expected_code"`
	Reason       string          `json:"reason"`
}

func TestFrozenDenialCorpus(t *testing.T) {
	input, err := os.ReadFile(filepath.Join(fixtureRoot, "denial-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus denialCorpus
	if err := json.Unmarshal(input, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "coh.deployment-profile-denials/v1" || corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 16 {
		t.Fatalf("denial corpus identity or inventory is invalid: %+v", corpus)
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if test.Name == "" || seen[test.Name] {
				t.Fatalf("missing or duplicate case name %q", test.Name)
			}
			seen[test.Name] = true
			base, readErr := os.ReadFile(filepath.Join(fixtureRoot, "valid", test.Base))
			if readErr != nil {
				t.Fatal(readErr)
			}
			mutated := applyMutation(t, base, test.Path, test.Value)
			decision, validationErr := evaluate(context.Background(), mutated)
			if Code(validationErr) != test.ExpectedCode || decision.ReasonCode != test.Reason || decision.Outcome == "allowed" {
				t.Fatalf("decision = %+v, code = %q, err = %v", decision, Code(validationErr), validationErr)
			}
		})
	}
}

func applyMutation(t *testing.T, input []byte, pointer string, rawValue json.RawMessage) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(input, &document); err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(rawValue, &value); err != nil {
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
	current[parts[len(parts)-1]] = value
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}
