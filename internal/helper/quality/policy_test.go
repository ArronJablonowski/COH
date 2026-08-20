package quality

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodePolicyAndToolLock(t *testing.T) {
	policy := loadPolicy(t)
	first, err := CanonicalPolicy(policy)
	if err != nil {
		t.Fatalf("CanonicalPolicy() error = %v", err)
	}
	second, err := CanonicalPolicy(policy)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("canonical policy is not stable: %v", err)
	}
	lockData := readRepoFile(t, "ci", "tools.lock.json")
	lock, digest, err := DecodeToolLock(lockData)
	if err != nil || len(lock.Tools) != 4 || len(lock.BinaryTools) != 1 || len(digest) != 64 {
		t.Fatalf("DecodeToolLock() = tools:%d binary:%d digest:%q err:%v", len(lock.Tools), len(lock.BinaryTools), digest, err)
	}
}

func TestDecodePolicyRejectsInvalidAndWeakenedInputs(t *testing.T) {
	if _, err := DecodePolicy([]byte(`{"schema_version":`)); CodeOf(err) != CodeInvalidInput {
		t.Fatalf("malformed code = %q, want %q", CodeOf(err), CodeInvalidInput)
	}
	policy := loadPolicy(t)
	policy.Stages = policy.Stages[:len(policy.Stages)-1]
	data, _ := json.Marshal(policy)
	if _, err := DecodePolicy(data); CodeOf(err) != CodeDenied {
		t.Fatalf("weakened policy code = %q, want %q", CodeOf(err), CodeDenied)
	}
	policy = loadPolicy(t)
	policy.Lanes[0].GoVersion = "1.26.6"
	data, _ = json.Marshal(policy)
	if _, err := DecodePolicy(data); CodeOf(err) != CodeDenied {
		t.Fatalf("changed lane code = %q, want %q", CodeOf(err), CodeDenied)
	}
	policy = loadPolicy(t)
	policy.Stages[0].TimeoutSeconds++
	data, _ = json.Marshal(policy)
	if _, err := DecodePolicy(data); CodeOf(err) != CodeDenied {
		t.Fatalf("changed timeout code = %q, want %q", CodeOf(err), CodeDenied)
	}
}

func TestDecodeToolLockRejectsPinDrift(t *testing.T) {
	data := readRepoFile(t, "ci", "tools.lock.json")
	tests := []struct {
		name   string
		mutate func(*ToolLock)
	}{
		{name: "version", mutate: func(lock *ToolLock) { lock.Tools[0].Version = "v0.0.0" }},
		{name: "module sum", mutate: func(lock *ToolLock) { lock.Tools[0].ModuleSum = "h1:drift" }},
		{name: "go mod sum", mutate: func(lock *ToolLock) { lock.Tools[0].GoModSum = "h1:drift" }},
		{name: "origin", mutate: func(lock *ToolLock) { lock.Tools[0].OriginHash = "drift" }},
		{name: "source route", mutate: func(lock *ToolLock) { lock.Tools[0].Module = "proxy.invalid/module" }},
		{name: "archive digest", mutate: func(lock *ToolLock) { lock.BinaryTools[0].Platforms[0].ArchiveSHA256 = "drift" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var lock ToolLock
			if err := json.Unmarshal(data, &lock); err != nil {
				t.Fatal(err)
			}
			test.mutate(&lock)
			changed, _ := json.Marshal(lock)
			_, _, err := DecodeToolLock(changed)
			if CodeOf(err) != CodeDenied {
				t.Fatalf("CodeOf() = %q, want denied", CodeOf(err))
			}
		})
	}
}

func FuzzDecodePolicy(f *testing.F) {
	f.Add(readRepoFile(f, "ci", "quality-policy.json"))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not-json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		policy, err := DecodePolicy(data)
		if err != nil {
			var qualityErr *Error
			if !errors.As(err, &qualityErr) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		if _, err := CanonicalPolicy(policy); err != nil {
			t.Fatalf("accepted policy cannot canonicalize: %v", err)
		}
	})
}

type testingReader interface {
	Helper()
	Fatalf(string, ...any)
}

func readRepoFile(t testingReader, elements ...string) []byte {
	t.Helper()
	parts := append([]string{"..", "..", ".."}, elements...)
	data, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	return data
}

func loadPolicy(t *testing.T) Policy {
	t.Helper()
	policy, err := DecodePolicy(readRepoFile(t, "ci", "quality-policy.json"))
	if err != nil {
		t.Fatalf("DecodePolicy() error = %v", err)
	}
	return policy
}
