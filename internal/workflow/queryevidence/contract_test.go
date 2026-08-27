package queryevidence

import (
	"context"
	"os"
	"testing"
)

func TestPublishedCanonicalFixture(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/query-evidence/v1/fixtures/record.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	value, canonical, err := DecodeRecord(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if value.Event != "started" || value.Completeness != "running" || string(canonical) != string(input[:len(input)-1]) {
		t.Fatal("published query evidence fixture is not canonical")
	}
}
