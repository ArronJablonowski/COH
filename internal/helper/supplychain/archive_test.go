package supplychain

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestArchiveIsDeterministicAndVerifiable(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "qualitygate")
	license := filepath.Join(directory, "LICENSE")
	if err := os.WriteFile(binary, []byte("binary\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(license, []byte("license\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs := []ArchiveInput{
		{Source: binary, Path: "bin/qualitygate", Mode: 0o555},
		{Source: license, Path: "share/coh/LICENSE", Mode: 0o444},
	}
	first := filepath.Join(directory, "first.tar.gz")
	second := filepath.Join(directory, "second.tar.gz")
	entries, err := CreateArchive(context.Background(), first, inputs)
	if err != nil {
		t.Fatal(err)
	}
	secondEntries, err := CreateArchive(context.Background(), second, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(entries, secondEntries) {
		t.Fatalf("entry records differ: %#v %#v", entries, secondEntries)
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(firstData, secondData) {
		t.Fatal("fixed inputs did not produce byte-identical archives")
	}
	if err := VerifyArchive(context.Background(), first, entries); err != nil {
		t.Fatal(err)
	}
	for name, suffix := range map[string][]byte{"trailing": []byte("junk"), "multistream": firstData} {
		path := filepath.Join(directory, name+".tar.gz")
		mutated := append(slices.Clone(firstData), suffix...)
		if err := os.WriteFile(path, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectArchive(context.Background(), path); CodeOf(err) != CodeDenied {
			t.Fatalf("%s stream code=%q err=%v", name, CodeOf(err), err)
		}
	}
	entries[0].SHA256 = string(make([]byte, 64))
	if err := VerifyArchive(context.Background(), first, entries); CodeOf(err) != CodeDenied {
		t.Fatalf("counterfeit entries code=%q err=%v", CodeOf(err), err)
	}
}

func TestArchiveRejectsUnsafeInputsAndCancellation(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(directory, "input")
	if err := os.WriteFile(input, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, archivePath := range []string{"../escape", "/absolute", "a\\b", "."} {
		output := filepath.Join(directory, "output-"+filepath.Base(archivePath)+".tar.gz")
		_, err := CreateArchive(context.Background(), output, []ArchiveInput{{Source: input, Path: archivePath, Mode: 0o444}})
		if CodeOf(err) != CodeInvalidInput {
			t.Fatalf("path=%q code=%q err=%v", archivePath, CodeOf(err), err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := CreateArchive(canceled, filepath.Join(directory, "canceled.tar.gz"), []ArchiveInput{{Source: input, Path: "input", Mode: 0o444}})
	if CodeOf(err) != CodeCanceled {
		t.Fatalf("canceled code=%q err=%v", CodeOf(err), err)
	}
	if _, statErr := os.Lstat(filepath.Join(directory, "canceled.tar.gz")); !os.IsNotExist(statErr) {
		t.Fatalf("canceled output survived: %v", statErr)
	}
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	_, err = CreateArchive(expired, filepath.Join(directory, "timeout.tar.gz"), []ArchiveInput{{Source: input, Path: "input", Mode: 0o444}})
	if CodeOf(err) != CodeTimeout {
		t.Fatalf("timeout code=%q err=%v", CodeOf(err), err)
	}
	if _, statErr := os.Lstat(filepath.Join(directory, "timeout.tar.gz")); !os.IsNotExist(statErr) {
		t.Fatalf("timed-out output survived: %v", statErr)
	}
}
