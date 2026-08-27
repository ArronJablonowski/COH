package splunkparser

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCommandPolicyRejectsEveryProhibitedCommandRecursively(t *testing.T) {
	t.Parallel()
	if len(prohibitedCommands) != 36 {
		t.Fatalf("prohibited command count = %d, want 36", len(prohibitedCommands))
	}
	for _, rule := range prohibitedCommands {
		rule := rule
		t.Run(rule.Name, func(t *testing.T) {
			t.Parallel()
			want := "spl_command_" + rule.Class
			outer := "search resource=endpoint | " + rule.Name + " value"
			nested := "search resource=endpoint host IN ([ search resource=endpoint | " + rule.Name + " value ]) | fields host"
			for location, input := range map[string]string{"outer": outer, "nested": nested} {
				_, err := parse(context.Background(), input)
				if err == nil || parseReason(err) != want {
					t.Fatalf("%s reason = %q (%v), want %q", location, parseReason(err), err, want)
				}
			}
		})
	}
}

func TestCommandPolicyRegistryIsExactAndFailClosed(t *testing.T) {
	t.Parallel()
	registry := builtinRegistry()
	if _, err := DecodeCommandRegistry(marshal(t, registry)); err != nil {
		t.Fatalf("built-in registry invalid: %v", err)
	}
	for _, input := range []string{
		"search resource=endpoint | geostats value",
		"search resource=endpoint | app_custom value",
		"search resource=endpoint host=\"`macro`\"",
	} {
		if _, err := parse(context.Background(), input); err == nil {
			t.Fatalf("unclassified or macro input accepted: %q", input)
		}
	}
}

func TestParserDenialCorpus(t *testing.T) {
	t.Parallel()
	var corpus DenialCorpus
	if err := json.Unmarshal(readFixture(t, "denial-corpus.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDenialCorpus(readFixture(t, "denial-corpus.json")); err != nil {
		t.Fatal(err)
	}
	for _, item := range corpus.Cases {
		item := item
		t.Run(item.Class, func(t *testing.T) {
			t.Parallel()
			request := validCompileRequest(t)
			request.Query = item.Input
			_, err := Compile(context.Background(), request)
			if err == nil || parseReason(err) != item.Reason {
				t.Fatalf("reason = %q (%v), want %q", parseReason(err), err, item.Reason)
			}
		})
	}
}
