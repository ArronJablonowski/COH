package architecturecatalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourcePolicyDeniesDynamicLoaderAndAlternateLaunch(t *testing.T) {
	tests := []struct {
		path    string
		content string
		want    string
	}{
		{"internal/example/loader.go", "package example\nimport _ \"plugin\"\n", "dynamic loader"},
		{"internal/example/main.go", "package main\n", "alternate launch path"},
	}
	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "cmd"), 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, filepath.FromSlash(test.path))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateSourcePolicy(root); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("mutation accepted or wrong denial: %v", err)
			}
		})
	}
}

func TestPublicationRedactionRejectsSensitiveAttributes(t *testing.T) {
	for _, name := range []string{"secret", "password", "credential", "token", "prompt", "content", "private_path"} {
		if !unsafeRecord(Record{ID: "record", Kind: "test", Attributes: []Attribute{attr(name, "redacted")}}) {
			t.Fatalf("sensitive attribute %q accepted", name)
		}
	}
}
