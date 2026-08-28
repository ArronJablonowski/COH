package sentinelsliceeval

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedSentinelSlicingContracts(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "evaluation", "sentinel-slicing", "v1")
	tests := []struct {
		name   string
		file   string
		decode func([]byte) error
	}{
		{name: "corpus", file: "sentinel-slicing-corpus.json", decode: func(input []byte) error { _, err := DecodeCorpus(input); return err }},
		{name: "environment", file: "sentinel-slicing-environment.json", decode: func(input []byte) error { _, err := DecodeEnvironment(input); return err }},
		{name: "recordings", file: "sentinel-recordings.json", decode: func(input []byte) error { _, err := DecodeRecordings(input); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join(root, test.file))
			if err != nil {
				t.Fatal(err)
			}
			if err := test.decode(input); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSentinelSlicingContractsRejectDuplicateKeys(t *testing.T) {
	input := []byte(`{"schema_version":"coh.sentinel-slicing-corpus/v1","schema_version":"coh.sentinel-slicing-corpus/v1"}`)
	if _, err := DecodeCorpus(input); err == nil {
		t.Fatal("duplicate key accepted")
	}
}
