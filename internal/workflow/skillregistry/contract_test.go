package skillregistry

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestFrozenSkillSchemasMatchStrictDecoder(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "skill", "v1")
	for _, name := range []string{
		"skill-manifest.schema.json", "signed-skill-manifest.schema.json", "skill-registry.schema.json",
	} {
		data, err := os.ReadFile(filepath.Join(root, name))
		var schema map[string]any
		if err != nil || json.Unmarshal(data, &schema) != nil ||
			schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("schema %s invalid: %v", name, err)
		}
	}
	manifest := readSchema(t, filepath.Join(root, "skill-manifest.schema.json"))
	assertRequired(t, manifest, manifestFields)
	envelope := readSchema(t, filepath.Join(root, "signed-skill-manifest.schema.json"))
	assertRequired(t, envelope, envelopeFields)
	registry := readSchema(t, filepath.Join(root, "skill-registry.schema.json"))
	definitions := registry["$defs"].(map[string]any)
	assertRequired(t, definitions["command"].(map[string]any), commandFields)
	assertRequired(t, definitions["signed_change"].(map[string]any), signedCommandFields)
}

func TestCanonicalPublicBuildersUseFrozenTimeAndDomains(t *testing.T) {
	fixture := newFixture(t)
	manifest := fixture.manifest(t, "1.0.0", "", "2")
	canonical, digest, err := CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte("2026-08-26T18:00:00.000000000Z")) ||
		!validDigest(digest) || bytes.Contains(canonical, []byte("Content")) {
		t.Fatalf("canonical manifest drift: %s %s", digest, canonical)
	}
	commandBytes, commandDigest, err := CanonicalChangeCommand(ChangeCommand{
		SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		CommandID: deterministicUUID("contract", "command"), Action: Promote,
		OrganizationID: testOrganization, TenantID: testTenant, CaseID: testCase, TaskID: testTask,
		ActorID: testOwner, SkillName: "timeline_builder", TargetManifestDigest: digest,
		ReasonDigest: testDigest("d"), CreatedAt: fixture.now.Add(-1), Deadline: fixture.now.Add(1),
	})
	if err != nil || !bytes.Contains(commandBytes, []byte(".999999999Z")) || !validDigest(commandDigest) {
		t.Fatalf("canonical command drift: %s %s %v", commandDigest, commandBytes, err)
	}
	policy := fixture.policy(ChangeCommand{
		OrganizationID: testOrganization, TenantID: testTenant, CaseID: testCase, TaskID: testTask,
		ActorID: testOwner, Action: Promote, SkillName: "timeline_builder", TargetManifestDigest: digest,
	}, "contract")
	prior := policy.DecisionDigest
	policy.TaskID = deterministicUUID("contract", "other-task")
	changed, err := DigestPolicyDecision(policy)
	if err != nil || prior == changed {
		t.Fatal("policy decision digest did not bind task scope")
	}
}

func TestResolvedSkillSurfaceContainsNoContentOrAuthorityHandle(t *testing.T) {
	typeOf := reflect.TypeOf(ResolvedSkill{})
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Interface ||
			field.Type == reflect.TypeOf([]byte{}) {
			t.Fatalf("resolved skill exposes authority-bearing field %s %v", field.Name, field.Type)
		}
		lower := strings.ToLower(field.Name)
		if lower == "content" || strings.Contains(lower, "path") || strings.Contains(lower, "url") ||
			strings.Contains(lower, "credential") || strings.Contains(lower, "executor") {
			t.Fatalf("resolved skill exposes forbidden field %s", field.Name)
		}
	}
}

func readSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertRequired(t *testing.T, schema map[string]any, expected []string) {
	t.Helper()
	raw, ok := schema["required"].([]any)
	if !ok {
		t.Fatal("schema required set missing")
	}
	actual := make([]string, len(raw))
	for index := range raw {
		actual[index], _ = raw[index].(string)
	}
	actual, wanted := slices.Clone(actual), slices.Clone(expected)
	slices.Sort(actual)
	slices.Sort(wanted)
	if !slices.Equal(actual, wanted) {
		t.Fatalf("required fields = %v, want %v", actual, wanted)
	}
}
