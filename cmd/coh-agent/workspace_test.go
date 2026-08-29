package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyChangeSetPreservesWorkspaceBoundary(t *testing.T) {
	workspace := t.TempDir()
	changes := changeSet{Summary: "Implemented the requested repair.",
		Files: []fileChange{{Path: "src/fix.py", Content: "def fixed():\n    return True\n"}}}
	if err := applyChangeSet(workspace, changes); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(filepath.Join(workspace, "src", "fix.py"))
	if err != nil || !strings.Contains(string(value), "return True") {
		t.Fatalf("change set was not applied: %q err=%v", value, err)
	}
	changes.Files[0].Path = "../escape"
	if err = applyChangeSet(workspace, changes); err == nil {
		t.Fatal("path traversal was accepted")
	}
	changes.Files[0].Path = ".git/config"
	if err = applyChangeSet(workspace, changes); err == nil {
		t.Fatal("git metadata mutation was accepted")
	}
}

func TestWorkspaceFingerprintIsStableAndDetectsChanges(t *testing.T) {
	workspace := t.TempDir()
	path := filepath.Join(workspace, "artifact.txt")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := fingerprintWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := fingerprintWorkspace(workspace)
	if first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatal("workspace fingerprint is not deterministic")
	}
	if err = os.WriteFile(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, _ := fingerprintWorkspace(workspace)
	if first == third {
		t.Fatal("workspace mutation did not change its artifact digest")
	}
}

func TestWorkspaceSymlinkFailsClosed(t *testing.T) {
	workspace := t.TempDir()
	if err := os.Symlink("/tmp", filepath.Join(workspace, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotWorkspace(workspace); err == nil {
		t.Fatal("workspace symlink was accepted")
	}
}

func TestQualifyOllamaDigestPreservesExactIdentity(t *testing.T) {
	raw := strings.Repeat("a", 64)
	qualified, err := qualifyOllamaDigest(raw)
	if err != nil || qualified != "sha256:"+raw {
		t.Fatalf("unexpected qualified digest %q: %v", qualified, err)
	}
	for _, invalid := range []string{"sha256:" + raw, strings.ToUpper(raw), strings.Repeat("z", 64)} {
		if _, err = qualifyOllamaDigest(invalid); err == nil {
			t.Fatalf("invalid Ollama digest was accepted: %q", invalid)
		}
	}
}

func TestDecodeChangeSetRequiresSingleToolCall(t *testing.T) {
	response := chatResponse{}
	response.Message.ToolCalls = []toolCall{{}}
	response.Message.ToolCalls[0].Function.Name = "submit_change_set"
	response.Message.ToolCalls[0].Function.Arguments = json.RawMessage(`{"summary":"done","files":[{"path":"submission.json","content":"{}"}],"deletes":[]}`)
	changes, err := decodeChangeSet(response)
	if err != nil || len(changes.Files) != 1 || changes.Files[0].Path != "submission.json" {
		t.Fatalf("valid tool call was rejected: %+v err=%v", changes, err)
	}
	response.Message.Content = "duplicate prose"
	if _, err = decodeChangeSet(response); err == nil {
		t.Fatal("dual-channel model response was accepted")
	}
	response.Message.Content = ""
	response.Message.ToolCalls = append(response.Message.ToolCalls, toolCall{})
	if _, err = decodeChangeSet(response); err == nil {
		t.Fatal("multiple tool calls were accepted")
	}
}
