package querybounds

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

const expectedAllowedDecisionDigest = "sha256:4940a003b677186b47bd925e2d42bdf0a7176f6b969d98c4beb6e7227741fa54"

func TestCanonicalAllowedDecisionFixture(t *testing.T) {
	input := readContractFile(t, "fixtures/allowed-decision.canonical.json")
	var decision Decision
	if err := json.Unmarshal(input, &decision); err != nil {
		t.Fatal(err)
	}
	canonical, err := VerifyDecision(decision)
	if err != nil || decision.DecisionDigest != expectedAllowedDecisionDigest || !bytes.Equal(canonical, bytes.TrimSpace(input)) {
		t.Fatalf("canonical=%t digest=%s err=%v", bytes.Equal(canonical, bytes.TrimSpace(input)), decision.DecisionDigest, err)
	}
}

func TestPublicSchemaAndDenialCorpusAreStrict(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(readContractFile(t, "query-bound-decision.schema.json"), &schema); err != nil ||
		schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["additionalProperties"] != false {
		t.Fatalf("schema identity err=%v", err)
	}
	required, ok := schema["required"].([]any)
	if !ok || len(required) != 30 {
		t.Fatalf("required fields=%d", len(required))
	}
	var corpus struct {
		SchemaVersion   string `json:"schema_version"`
		ContractVersion string `json:"contract_version"`
		Cases           []struct {
			Reason    string `json:"reason"`
			Class     string `json:"class"`
			CoveredBy string `json:"covered_by"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readContractFile(t, "fixtures/denial-corpus.json"), &corpus); err != nil ||
		corpus.SchemaVersion != "coh.query-bound-denials/v1" || corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 24 {
		t.Fatalf("corpus=%+v err=%v", corpus, err)
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for _, item := range corpus.Cases {
		if !reasonPattern.MatchString(item.Reason) || item.Class == "" || item.CoveredBy == "" || seen[item.Reason] {
			t.Fatalf("invalid corpus item=%+v", item)
		}
		seen[item.Reason] = true
	}
	for _, required := range []string{"actor_revoked", "source_revoked", "allowlist_revoked", "capability_revoked",
		"approval_denied", "changed_replay", "future_unsafe", "limits_excessive", "audit_unavailable"} {
		if !seen[required] {
			t.Fatalf("missing denial reason %s", required)
		}
	}
}

func readContractFile(t testing.TB, name string) []byte {
	t.Helper()
	input, err := os.ReadFile("../../../contracts/query-bounds/v1/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return input
}
