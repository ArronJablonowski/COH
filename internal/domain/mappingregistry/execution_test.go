package mappingregistry

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestExecuteMappingAppliesClosedLanguageDeterministically(t *testing.T) {
	manifest := executionManifest()
	result, err := executeMapping(context.Background(), manifest, originalObject(t,
		`{"event":{"kind":"login","success":true},"host":{"name":"WS-01"},"process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`))
	if err != nil {
		t.Fatalf("executeMapping() err=%v", err)
	}
	wantOCSF := `{"activity_name":"logon","device":{"name":"WS-01"},"metadata":{"version":"1.9.0"},"process":{"pid":42}}`
	wantECS := `{"event":{"created":"2026-08-27T01:02:03Z","success":"true"}}`
	if string(result.OCSF) != wantOCSF || string(result.ECS) != wantECS {
		t.Fatalf("OCSF=%s ECS=%s", result.OCSF, result.ECS)
	}
	wantRules := []string{"host-name", "ocsf-version", "event-kind", "process-id", "event-success", "event-time"}
	wantPaths := []string{"original.event.kind", "original.event.success", "original.host.name", "original.process.pid", "original.time"}
	if !reflect.DeepEqual(result.AppliedRules, wantRules) || !reflect.DeepEqual(result.MappedPaths, wantPaths) ||
		len(result.MissingPaths) != 0 || len(result.LossyPaths) != 0 {
		t.Fatalf("result=%+v", result)
	}

	again, err := executeMapping(context.Background(), manifest, originalObject(t,
		`{"event":{"kind":"login","success":true},"host":{"name":"WS-01"},"process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`))
	if err != nil || string(again.OCSF) != string(result.OCSF) || string(again.ECS) != string(result.ECS) {
		t.Fatalf("repeat=%+v err=%v", again, err)
	}
}

func TestExecuteMappingRecordsOptionalAbsence(t *testing.T) {
	manifest := executionManifest()
	manifest.Rules[0].Required = false
	result, err := executeMapping(context.Background(), manifest, originalObject(t,
		`{"event":{"kind":"login","success":true},"process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.MissingPaths, []string{"original.host.name"}) || strings.Contains(string(result.OCSF), "device") {
		t.Fatalf("result=%+v OCSF=%s", result, result.OCSF)
	}
}

func TestExecuteMappingSupportsIntegerStringAndNullScalarOutputs(t *testing.T) {
	manifest := validManifest()
	count := "original.event.count"
	manifest.Rules = []Rule{
		executionRule("event-count", 1, ToString, &count, "ecs", "ecs.event.count", Integer, String),
		{
			RuleID: "null-observable", Sequence: 2, Operation: Constant,
			OutputNamespace: "ocsf", OutputPath: "ocsf.observable.value", InputType: Null, OutputType: Null,
			ConstantValue: json.RawMessage(`null`), EnumTable: []EnumEntry{},
			Reversibility: "not_reversible", LossState: "lossless", LossReason: "constant",
		},
	}
	manifest.IgnoredFields = []IgnoredField{}
	result, err := executeMapping(context.Background(), manifest, originalObject(t, `{"event":{"count":17}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(result.OCSF) != `{"observable":{"value":null}}` || string(result.ECS) != `{"event":{"count":"17"}}` {
		t.Fatalf("OCSF=%s ECS=%s", result.OCSF, result.ECS)
	}
}

func TestExecuteMappingDeniesDataAndConversionFailures(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		reason Reason
	}{
		{"required missing", `{"event":{"kind":"login","success":true},"process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`, TypeMismatch},
		{"intermediate scalar", `{"event":{"kind":"login","success":true},"host":"not-object","process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`, TypeMismatch},
		{"wrong type", `{"event":{"kind":"login","success":true},"host":{"name":7},"process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`, TypeMismatch},
		{"array value", `{"event":{"kind":"login","success":true},"host":{"name":["WS-01"]},"process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`, TypeMismatch},
		{"enum miss", `{"event":{"kind":"logout","success":true},"host":{"name":"WS-01"},"process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`, TypeMismatch},
		{"noncanonical integer text", `{"event":{"kind":"login","success":true},"host":{"name":"WS-01"},"process":{"pid":"042"},"time":"2026-08-27T01:02:03Z"}`, TypeMismatch},
		{"integer overflow", `{"event":{"kind":"login","success":true},"host":{"name":"WS-01"},"process":{"pid":"9223372036854775808"},"time":"2026-08-27T01:02:03Z"}`, ConversionOverflow},
		{"range overflow", `{"event":{"kind":"login","success":true},"host":{"name":"WS-01"},"process":{"pid":"70000"},"time":"2026-08-27T01:02:03Z"}`, ConversionOverflow},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := executeMapping(context.Background(), executionManifest(), originalObject(t, test.input))
			if Code(err) != InvalidInput || ErrorReason(err) != test.reason {
				t.Fatalf("err=%v code=%q reason=%q", err, Code(err), ErrorReason(err))
			}
		})
	}
}

func TestExecuteMappingEnforcesValueBoundAndContext(t *testing.T) {
	manifest := executionManifest()
	manifest.Limits.MaxValueBytes = 8
	input := `{"event":{"kind":"login","success":true},"host":{"name":"value-too-long"},"process":{"pid":"42"},"time":"2026-08-27T01:02:03Z"}`
	if _, err := executeMapping(context.Background(), manifest, originalObject(t, input)); ErrorReason(err) != TypeMismatch {
		t.Fatalf("value bound err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executeMapping(canceled, executionManifest(), originalObject(t, input)); Code(err) != CanceledError || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation err=%v", err)
	}
}

func executionManifest() Manifest {
	manifest := validManifest()
	host, kind := "original.host.name", "original.event.kind"
	pid, success, eventTime := "original.process.pid", "original.event.success", "original.time"
	manifest.Rules = []Rule{
		executionRule("host-name", 1, Copy, &host, "ocsf", "ocsf.device.name", String, String),
		{RuleID: "ocsf-version", Sequence: 2, Operation: Constant, OutputNamespace: "ocsf", OutputPath: "ocsf.metadata.version",
			InputType: String, OutputType: String, ConstantValue: json.RawMessage(`"1.9.0"`), EnumTable: []EnumEntry{},
			Reversibility: "not_reversible", LossState: "lossless", LossReason: "constant"},
		executionEnumRule(kind),
		executionIntegerRule(pid),
		executionRule("event-success", 5, ToString, &success, "ecs", "ecs.event.success", Boolean, String),
		executionRule("event-time", 6, TimestampReference, &eventTime, "ecs", "ecs.event.created", TimestampText, TimestampText),
	}
	manifest.IgnoredFields = []IgnoredField{}
	manifest.Limits.MaxRules = 16
	return manifest
}

func executionRule(id string, sequence uint16, operation Operation, input *string, namespace, output string, inputType, outputType ValueType) Rule {
	return Rule{RuleID: id, Sequence: sequence, Operation: operation, InputPath: input,
		OutputNamespace: namespace, OutputPath: output, InputType: inputType, OutputType: outputType,
		Required: true, ConstantValue: json.RawMessage(`null`), EnumTable: []EnumEntry{},
		Reversibility: "reversible", LossState: "lossless", LossReason: "none"}
}

func executionEnumRule(input string) Rule {
	rule := executionRule("event-kind", 3, Enum, &input, "ocsf", "ocsf.activity_name", String, String)
	rule.EnumTable = []EnumEntry{{Source: json.RawMessage(`"login"`), Target: json.RawMessage(`"logon"`)}}
	return rule
}

func executionIntegerRule(input string) Rule {
	rule := executionRule("process-id", 4, ToInteger, &input, "ocsf", "ocsf.process.pid", String, Integer)
	rule.IntegerRange = &IntegerRange{Minimum: 0, Maximum: 65_535}
	return rule
}

func originalObject(t *testing.T, input string) map[string]any {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
