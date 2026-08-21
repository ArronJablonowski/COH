package domaincontract

import (
	"bytes"
	"errors"
	"testing"
)

func TestCanonicalizeDeterministicAndIdempotent(t *testing.T) {
	input := []byte(" { \"z\" : [3,2,1], \"a\":\"<>&/é\", \"n\":-12 } ")
	want := []byte(`{"a":"<>&/é","n":-12,"z":[3,2,1]}`)
	got, err := Canonicalize(input)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Canonicalize()=%s err=%v", got, err)
	}
	again, err := Canonicalize(got)
	if err != nil || !bytes.Equal(again, want) {
		t.Fatalf("Canonicalize(canonical)=%s err=%v", again, err)
	}
}

func TestCanonicalizeRejectsNonIntegerNumbers(t *testing.T) {
	for _, input := range []string{`1.0`, `1e2`, `-0`} {
		if _, err := Canonicalize([]byte(input)); !errors.Is(err, ErrDenied) {
			t.Fatalf("Canonicalize(%q) err=%v", input, err)
		}
	}
}

func TestCanonicalizeDoesNotMutateInput(t *testing.T) {
	input := []byte(`{"b":2,"a":1}`)
	original := append([]byte(nil), input...)
	if _, err := Canonicalize(input); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, original) {
		t.Fatal("Canonicalize mutated source input")
	}
}
