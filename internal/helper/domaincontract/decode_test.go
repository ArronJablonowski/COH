package domaincontract

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeUniqueAcceptsOneValue(t *testing.T) {
	value, err := DecodeUnique([]byte(`{"a":[1,true,null],"b":{"c":"x"}}`))
	if err != nil || value == nil {
		t.Fatalf("DecodeUnique() value=%v err=%v", value, err)
	}
}

func TestDecodeUniqueRejectsDuplicateFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "domain", "v1", "fixtures", "denied", "duplicate-key.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeUnique(input); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("DecodeUnique() err=%v", err)
	}
}

func TestDecodeUniqueDenials(t *testing.T) {
	cases := map[string][]byte{
		"empty":     nil,
		"oversized": make([]byte, MaxInputBytes+1),
		"malformed": []byte(`{"a":`),
		"trailing":  []byte(`{} {}`),
		"deep":      []byte(strings.Repeat("[", 66) + strings.Repeat("]", 66)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUnique(input); !errors.Is(err, ErrDenied) {
				t.Fatalf("DecodeUnique() err=%v", err)
			}
		})
	}
}
