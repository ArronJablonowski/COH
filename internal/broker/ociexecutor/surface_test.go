package ociexecutor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionSurfaceHasNoShellGenericNetworkOrHostMountPrimitive(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		source := string(data)
		for _, forbidden := range []string{"net/http", "plugin", "syscall.Exec", "sh -c", "bash -c", "--privileged",
			"--volume", "--mount", "--device", "docker.sock", "--network=host", "--pid=host", "--ipc=host"} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s contains forbidden production surface %q", entry.Name(), forbidden)
			}
		}
		if strings.Contains(source, "os/exec") && entry.Name() != "runtime_docker.go" {
			t.Fatalf("%s imports os/exec outside the bounded runtime", entry.Name())
		}
	}
}
