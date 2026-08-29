package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const maximumWorkspaceBytes = 8 << 20

func snapshotWorkspace(root string) (string, error) {
	var snapshot strings.Builder
	err := walkWorkspace(root, func(relative, path string, entry fs.DirEntry) error {
		value, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if snapshot.Len()+len(value) > maximumWorkspaceBytes {
			return errors.New("workspace snapshot exceeds 8 MiB")
		}
		fmt.Fprintf(&snapshot, "\n--- FILE: %s ---\n", relative)
		snapshot.Write(value)
		return nil
	})
	return snapshot.String(), err
}

func fingerprintWorkspace(root string) (string, error) {
	type record struct{ path, digest string }
	records := []record{}
	err := walkWorkspace(root, func(relative, path string, entry fs.DirEntry) error {
		value, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(value)
		records = append(records, record{relative, hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return "", err
	}
	slices.SortFunc(records, func(left, right record) int { return strings.Compare(left.path, right.path) })
	var canonical strings.Builder
	for _, item := range records {
		canonical.WriteString(item.path)
		canonical.WriteByte(0)
		canonical.WriteString(item.digest)
		canonical.WriteByte('\n')
	}
	return digestBytes([]byte("COH-WORKSPACE-ARTIFACT-V1\x00" + canonical.String())), nil
}

func walkWorkspace(root string, visit func(string, string, fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("workspace symbolic links are denied")
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || !safeRelative(relative) {
			return errors.New("workspace path escaped its boundary")
		}
		return visit(filepath.ToSlash(relative), path, entry)
	})
}

func applyChangeSet(root string, changes changeSet) error {
	if len(changes.Files) > 64 || len(changes.Deletes) > 64 || strings.TrimSpace(changes.Summary) == "" {
		return errors.New("model change set bounds are invalid")
	}
	seen, total := map[string]struct{}{}, 0
	for _, change := range changes.Files {
		if !safeRelative(change.Path) {
			return errors.New("model change path is unsafe")
		}
		path := filepath.Join(root, filepath.FromSlash(change.Path))
		if _, exists := seen[path]; exists {
			return errors.New("model change set contains duplicate paths")
		}
		seen[path], total = struct{}{}, total+len(change.Content)
		if total > maximumWorkspaceBytes {
			return errors.New("model change set exceeds 8 MiB")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("model cannot replace a symbolic link")
		}
		if err := os.WriteFile(path, []byte(change.Content), 0o600); err != nil {
			return err
		}
	}
	for _, relative := range changes.Deletes {
		if !safeRelative(relative) {
			return errors.New("model delete path is unsafe")
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		if _, exists := seen[path]; exists {
			return errors.New("model cannot write and delete the same path")
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("model delete target is not a regular file")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

func safeRelative(value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.ContainsRune(value, 0) || strings.Contains(value, "\\") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".git" || part == ".ssh" || part == ".env" {
			return false
		}
	}
	return true
}
