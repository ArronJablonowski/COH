package caselifecycle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestPublishedCaseLifecycleSchemaIsStrictAndFrozen(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "case", "v1", "case-lifecycle.schema.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err = json.Unmarshal(input, &schema); err != nil || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema invalid: %v", err)
	}
	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("definitions missing")
	}
	for _, name := range []string{"case", "command", "authorization_request", "decision", "record", "receipt"} {
		definition, exists := definitions[name].(map[string]any)
		if !exists || definition["additionalProperties"] != false {
			t.Fatalf("%s is not closed", name)
		}
		required, requiredOK := definition["required"].([]any)
		properties, propertiesOK := definition["properties"].(map[string]any)
		if !requiredOK || !propertiesOK || len(required) != len(properties) {
			t.Fatalf("%s does not require every field", name)
		}
	}
	wantOperations := []string{"assign", "classify", "close", "create", "delete", "export", "place_hold", "release_hold", "reopen"}
	wantStates := []string{"closed", "deleted", "open"}
	wantClassifications := []string{"confidential", "internal", "public", "restricted"}
	for name, want := range map[string][]string{"operation": wantOperations, "state": wantStates, "classification": wantClassifications} {
		definition := definitions[name].(map[string]any)
		values := stringsFromJSON(t, definition["enum"])
		sort.Strings(values)
		if !reflect.DeepEqual(values, want) {
			t.Fatalf("%s=%v want=%v", name, values, want)
		}
	}
}

func TestCanonicalWireFieldsMatchPublishedCaseSchema(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "case", "v1", "case-lifecycle.schema.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Definitions map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"$defs"`
	}
	if err = json.Unmarshal(input, &schema); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"case": caseWire{}, "command": commandWire{}, "authorization_request": authorizationWire{},
		"decision": decisionWire{}, "record": recordWire{}, "receipt": receiptWire{},
	} {
		want := make([]string, 0, len(schema.Definitions[name].Properties))
		for field := range schema.Definitions[name].Properties {
			want = append(want, field)
		}
		sort.Strings(want)
		got := jsonFields(reflect.TypeOf(value))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s wire=%v schema=%v", name, got, want)
		}
	}
}

func TestCanonicalBindingsCoverScopeActorPolicyTimeAndProvenance(t *testing.T) {
	command := validCreateCommand()
	first, err := CommandBindingDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Command){
		func(value *Command) { value.Case.TenantID = testDecision },
		func(value *Command) { value.ActorRevision++ },
		func(value *Command) { value.PolicyDigest = testDigest("other-policy") },
		func(value *Command) { value.Deadline = value.Deadline.Add(time.Second) },
	}
	for index, mutate := range mutations {
		candidate := cloneCommand(command)
		mutate(&candidate)
		bound, bindErr := CommandBindingDigest(candidate)
		if bindErr != nil || bound == first {
			t.Fatalf("mutation %d was not bound: digest=%s err=%v", index, bound, bindErr)
		}
	}
	authorization := validAuthorization(command)
	decision := validDecision(command, authorization)
	record := validRecord(command, decision)
	receipt := validReceipt(command, decision, record)
	if validateAuthorization(authorization) != nil || validateDecision(decision) != nil ||
		validateRecord(record) != nil || validateReceipt(receipt) != nil {
		t.Fatal("valid canonical records were rejected")
	}
	tampered := cloneReceipt(receipt)
	tampered.Record.AssigneeActorID = testDecision
	if validateReceipt(tampered) == nil {
		t.Fatal("tampered nested record was accepted")
	}
}

func TestOperationSpecificFieldsAndRecordInvariantsFailClosed(t *testing.T) {
	command := validCreateCommand()
	reason := testDigest("reason")
	command.ReasonDigest = &reason
	if CodeOf(validateCommandShape(command)) != InvalidInput {
		t.Fatal("inapplicable create reason was accepted")
	}
	command = validCreateCommand()
	command.Operation = Delete
	command.ExpectedRevision = 1
	command.TargetClassification = nil
	command.AssigneeActorID = nil
	command.RetentionPolicyID = nil
	command.RetainUntil = nil
	command.ReasonDigest = &reason
	if err := validateCommandShape(command); err != nil {
		t.Fatalf("valid delete shape rejected: %v", err)
	}
	authorization := validAuthorization(validCreateCommand())
	decision := validDecision(validCreateCommand(), authorization)
	record := validRecord(validCreateCommand(), decision)
	record.LegalHold = true
	record.HoldReasonDigest = &reason
	record.ProvenanceDigest, _ = RecordProvenanceDigest(record)
	if err := validateRecord(record); err != nil {
		t.Fatalf("held active record rejected: %v", err)
	}
	record.State = Deleted
	record.DeletionReasonDigest = &reason
	deletedBy := testActor
	record.DeletedByActorID = &deletedBy
	record.UpdatedAt = record.RetainUntil
	record.ProvenanceDigest, _ = RecordProvenanceDigest(record)
	if validateRecord(record) == nil {
		t.Fatal("held deletion record was accepted")
	}
	if !(classificationRank(Public) < classificationRank(Internal) &&
		classificationRank(Internal) < classificationRank(Confidential) &&
		classificationRank(Confidential) < classificationRank(Restricted)) {
		t.Fatal("classification order changed")
	}
}

func jsonFields(value reflect.Type) []string {
	result := make([]string, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		result = append(result, value.Field(index).Tag.Get("json"))
	}
	sort.Strings(result)
	return result
}

func stringsFromJSON(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("enum is not an array: %T", value)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, textOK := item.(string)
		if !textOK {
			t.Fatalf("enum value is not text: %T", item)
		}
		result = append(result, text)
	}
	return result
}
