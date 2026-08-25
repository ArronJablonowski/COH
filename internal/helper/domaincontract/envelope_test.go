package domaincontract

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateEnvelopeFixture(t *testing.T) {
	input := readFixture(t, "envelope.valid.json")
	canonical, err := ValidateEnvelope(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ValidateEnvelope(context.Background(), canonical)
	if err != nil || string(again) != string(canonical) {
		t.Fatalf("recovery validation changed bytes: %s err=%v", again, err)
	}
}

func TestValidateEnvelopeDenialFixtures(t *testing.T) {
	for _, name := range []string{"bad-timestamp.json", "duplicate-key.json", "unknown-field.json", "unsupported-version.json"} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateEnvelope(context.Background(), readFixture(t, "denied", name)); !errors.Is(err, ErrDenied) {
				t.Fatalf("ValidateEnvelope() err=%v", err)
			}
		})
	}
}

func TestValidateEnvelopeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ValidateEnvelope(ctx, readFixture(t, "envelope.valid.json")); !errors.Is(err, ErrCancelled) {
		t.Fatalf("ValidateEnvelope() err=%v", err)
	}
}

func TestValidateEnvelopeTimeoutAndRecovery(t *testing.T) {
	input := readFixture(t, "envelope.valid.json")
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	output, err := ValidateEnvelope(ctx, input)
	if !errors.Is(err, ErrTimeout) || output != nil {
		t.Fatalf("timeout output=%s err=%v", output, err)
	}
	if _, err := ValidateEnvelope(context.Background(), input); err != nil {
		t.Fatalf("same-input recovery failed: %v", err)
	}
}

func TestValidateEnvelopeAdditionalDenials(t *testing.T) {
	inputs := []string{
		`{"schema":"coh.domain/v1","kind":"case","id":"BAD","organization_id":"0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e","tenant_id":"0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16","case_id":null,"revision":1,"created_at":"2026-08-21T20:00:00.000000000Z","data":{}}`,
		`{"schema":"coh.domain/v1","kind":"case","id":"0198d6c4-7618-7d31-8e0a-9da53cae8ca2","organization_id":"0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e","tenant_id":"0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16","case_id":null,"revision":1.5,"created_at":"2026-08-21T20:00:00.000000000Z","data":{}}`,
	}
	for _, input := range inputs {
		if _, err := ValidateEnvelope(context.Background(), []byte(input)); !errors.Is(err, ErrDenied) {
			t.Fatalf("ValidateEnvelope() err=%v", err)
		}
	}
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "..", "contracts", "domain", "v1", "fixtures"}, parts...)...)
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return input
}
