package evidenceingest

import (
	"context"
	"reflect"
	"sort"
	"testing"
)

func TestCanonicalBindingsCoverIdentityTransportManifestAndReceipt(t *testing.T) {
	command := validCommand()
	authorization := validAuthorization(command)
	decision := validDecision(command, authorization)
	manifest := validManifest(command, authorization, decision)
	receipt := validReceipt(command, authorization, decision, manifest)
	if validateCommand(command, testNow) != nil || validateAuthorization(authorization) != nil ||
		validateDecision(decision) != nil || validateManifest(manifest) != nil || validateReceipt(receipt) != nil {
		t.Fatal("valid canonical fixture was rejected")
	}
	mutations := []func(*Command){
		func(value *Command) { value.Case.TenantID = "0199a314-1010-7010-8010-000000000010" },
		func(value *Command) { value.ActorRevision++ },
		func(value *Command) { value.PolicyDigest = testDigest("changed-policy") },
		func(value *Command) { value.Transport.ChannelBindingDigest = testDigest("changed-channel") },
		func(value *Command) { value.Source.Identity = "changed" },
	}
	original, _ := CommandBindingDigest(command)
	for index, mutate := range mutations {
		changed := command
		mutate(&changed)
		bound, err := CommandBindingDigest(changed)
		if index == len(mutations)-1 {
			if err == nil {
				t.Fatal("source identity changed without matching identity digest")
			}
			continue
		}
		if err != nil || bound == original {
			t.Fatalf("command mutation %d was not bound: %v", index, err)
		}
	}
	tamperedManifest := manifest
	tamperedManifest.Source.Identity = "changed"
	if validateManifest(tamperedManifest) == nil {
		t.Fatal("manifest source tamper was accepted")
	}
	tamperedReceipt := receipt
	tamperedReceipt.EncryptedArtifact.LocatorDigest = testDigest("changed-locator")
	if validateReceipt(tamperedReceipt) == nil {
		t.Fatal("receipt encrypted-object tamper was accepted")
	}
	formatted := formatTime(testNow)
	if parsed, err := parseTime(formatted); err != nil || parsed != testNow {
		t.Fatalf("canonical timestamp round trip failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if CodeOf(contextError(ctx)) != Canceled {
		t.Fatal("canceled context did not produce a typed error")
	}
}

func TestCanonicalWireFieldsMatchPublishedSchema(t *testing.T) {
	definitions := loadSchemaDefinitions(t)
	tests := map[string]any{
		"case": caseWire{}, "artifact": artifactWire{}, "observed_time": observedTimeWire{},
		"source_range": sourceRangeWire{}, "source": sourceWire{}, "component": componentWire{},
		"transport": transportWire{}, "command": commandWire{}, "authorization_request": authorizationWire{},
		"decision": decisionWire{}, "artifact_manifest": manifestWire{}, "encrypted_object": encryptedObjectWire{},
		"published_object": publishedObjectWire{}, "receipt": receiptWire{},
	}
	for definition, wire := range tests {
		object := definitions[definition].(map[string]any)
		properties := object["properties"].(map[string]any)
		want := make([]string, 0, len(properties))
		for name := range properties {
			want = append(want, name)
		}
		sort.Strings(want)
		got := jsonFields(reflect.TypeOf(wire))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s wire=%v schema=%v", definition, got, want)
		}
	}
}

func loadSchemaDefinitions(t *testing.T) map[string]any {
	t.Helper()
	return schemaDefinitions(t)
}

func jsonFields(value reflect.Type) []string {
	result := make([]string, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		result = append(result, value.Field(index).Tag.Get("json"))
	}
	sort.Strings(result)
	return result
}
