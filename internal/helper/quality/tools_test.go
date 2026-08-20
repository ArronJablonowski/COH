package quality

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifiedExecutableDigestRejectsTamperSymlinkAndOversize(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tool")
	if err := os.WriteFile(path, []byte("trusted"), 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := verifiedExecutableDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("appended")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := verifiedExecutableDigest(path)
	if err != nil || after == before {
		t.Fatalf("appended executable digest=%q err=%v", after, err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedExecutableDigest(link); err == nil {
		t.Fatal("symlinked tool was accepted")
	}
	large := filepath.Join(directory, "large")
	largeFile, err := os.OpenFile(large, os.O_CREATE|os.O_WRONLY, 0o500)
	if err != nil {
		t.Fatal(err)
	}
	if err := largeFile.Truncate(maximumToolSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := largeFile.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedExecutableDigest(large); err == nil {
		t.Fatal("oversized tool was accepted")
	}
}

func TestVerifyToolDirectoryNamesRejectsExtraAndMissingEntries(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"first", "second"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o500); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyToolDirectoryNames(directory, []string{"first", "second"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "git"), []byte("fake"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := verifyToolDirectoryNames(directory, []string{"first", "second"}); CodeOf(err) != CodeDenied {
		t.Fatalf("extra executable code=%q, want denied", CodeOf(err))
	}
	if err := os.Remove(filepath.Join(directory, "git")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, "second")); err != nil {
		t.Fatal(err)
	}
	if err := verifyToolDirectoryNames(directory, []string{"first", "second"}); CodeOf(err) != CodeDenied {
		t.Fatalf("missing executable code=%q, want denied", CodeOf(err))
	}
}
