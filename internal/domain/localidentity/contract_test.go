package localidentity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const identityFixtureRoot = "../../../contracts/identity/v1/fixtures"

var validFixturePairs = map[string]string{
	"administrator-config.request.json": "analyst-administrator.actor.json",
	"analyst-query.request.json":        "analyst-administrator.actor.json",
	"approver-t3.request.json":          "approver.actor.json",
	"auditor-audit.request.json":        "auditor.actor.json",
	"service-invoke.request.json":       "service.actor.json",
}

func TestFrozenIdentityFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(identityFixtureRoot, "valid", "*.json"))
	if err != nil || len(paths) != 9 {
		t.Fatalf("valid fixture inventory = %d, err = %v", len(paths), err)
	}
	for _, path := range paths {
		name := filepath.Base(path)
		if strings.HasSuffix(name, ".actor.json") {
			input := readIdentityFixture(t, name)
			if _, decodeErr := DecodeActor(input); decodeErr != nil {
				t.Fatalf("actor %s: %v", name, decodeErr)
			}
		}
	}
	if len(validFixturePairs) != 5 {
		t.Fatalf("request pair inventory = %d", len(validFixturePairs))
	}
	for requestName, actorName := range validFixturePairs {
		t.Run(requestName, func(t *testing.T) {
			actor, actorErr := DecodeActor(readIdentityFixture(t, actorName))
			request, requestErr := DecodeRequest(readIdentityFixture(t, requestName))
			if actorErr != nil || requestErr != nil {
				t.Fatalf("actor err = %v, request err = %v", actorErr, requestErr)
			}
			decision, authorizationErr := EvaluateRBAC(actor, request)
			if authorizationErr != nil || decision.Outcome != "allowed" {
				t.Fatalf("decision = %+v, err = %v", decision, authorizationErr)
			}
		})
	}
}

type identityDenialCorpus struct {
	Schema          string               `json:"schema"`
	ContractVersion string               `json:"contract_version"`
	Cases           []identityDenialCase `json:"cases"`
}

type identityDenialCase struct {
	Name         string          `json:"name"`
	Document     string          `json:"document"`
	Base         string          `json:"base"`
	Counterpart  string          `json:"counterpart"`
	Operation    string          `json:"operation"`
	Path         string          `json:"path"`
	Value        json.RawMessage `json:"value,omitempty"`
	SecondPath   string          `json:"second_path,omitempty"`
	SecondValue  json.RawMessage `json:"second_value,omitempty"`
	ExpectedCode ErrorCode       `json:"expected_code"`
	Reason       string          `json:"reason"`
}

func TestFrozenIdentityDenialCorpus(t *testing.T) {
	input, err := os.ReadFile(filepath.Join(identityFixtureRoot, "denial-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus identityDenialCorpus
	if err := json.Unmarshal(input, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "coh.local-identity-denials/v1" || corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 22 {
		t.Fatalf("denial corpus identity or inventory is invalid: %+v", corpus)
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if test.Name == "" || seen[test.Name] {
				t.Fatalf("missing or duplicate case name %q", test.Name)
			}
			seen[test.Name] = true
			mutated := mutateIdentityDocument(t, readIdentityFixture(t, test.Base), test.Operation, test.Path, test.Value)
			if test.SecondPath != "" {
				mutated = mutateIdentityDocument(t, mutated, "set", test.SecondPath, test.SecondValue)
			}
			var decision Decision
			var evaluationErr error
			switch test.Document {
			case "actor":
				actor, decodeErr := DecodeActor(mutated)
				if decodeErr != nil {
					evaluationErr = decodeErr
				} else {
					request := mustDecodeRequest(t, readIdentityFixture(t, test.Counterpart))
					decision, evaluationErr = EvaluateRBAC(actor, request)
				}
			case "request":
				request, decodeErr := DecodeRequest(mutated)
				if decodeErr != nil {
					evaluationErr = decodeErr
				} else {
					actor := mustDecodeActor(t, readIdentityFixture(t, test.Counterpart))
					decision, evaluationErr = EvaluateRBAC(actor, request)
				}
			default:
				t.Fatalf("unknown document type %q", test.Document)
			}
			if Code(evaluationErr) != test.ExpectedCode || errorReason(evaluationErr) != test.Reason || decision.Outcome == "allowed" {
				t.Fatalf("decision = %+v, code = %q, reason = %q, err = %v", decision, Code(evaluationErr), errorReason(evaluationErr), evaluationErr)
			}
		})
	}
}

func readIdentityFixture(t *testing.T, name string) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join(identityFixtureRoot, "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func mustDecodeActor(t *testing.T, input []byte) Actor {
	t.Helper()
	actor, err := DecodeActor(input)
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func mustDecodeRequest(t *testing.T, input []byte) Request {
	t.Helper()
	request, err := DecodeRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mutateIdentityDocument(t *testing.T, input []byte, operation, pointer string, rawValue json.RawMessage) []byte {
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
