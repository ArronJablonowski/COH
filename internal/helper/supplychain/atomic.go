package supplychain

import (
	"errors"
	"os"
	"path/filepath"
)

func writeAtomicNoReplace(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return errorf(CodeInvalidInput, "output", "output filename is required", nil)
	}
	if err := rejectSymlinkAncestors(directory); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errorf(CodeDenied, "output", "output parent must be a private real directory", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errorf(CodeDenied, "output", "output must not already exist", err)
	}
	temporary, err := os.CreateTemp(directory, ".coh-release-*")
	if err != nil {
		return errorf(CodeToolFailure, "output", "cannot create sibling temporary file", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	failed := true
	defer func() {
		if failed {
			temporary.Close()
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return errorf(CodeToolFailure, "output", "cannot set output permissions", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return errorf(CodeToolFailure, "output", "cannot write output", err)
	}
	if err := temporary.Sync(); err != nil {
		return errorf(CodeToolFailure, "output", "cannot sync output", err)
	}
	if err := temporary.Close(); err != nil {
		return errorf(CodeToolFailure, "output", "cannot close output", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return errorf(CodeDenied, "output", "cannot publish without replacing destination", err)
	}
	failed = false
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return errorf(CodeToolFailure, "output", "cannot open output directory", err)
	}
	defer directoryHandle.Close()
	openedInfo, err := directoryHandle.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return errorf(CodeDenied, "output", "output directory identity changed during publication", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		return errorf(CodeToolFailure, "output", "cannot sync output directory", err)
	}
	after, err := os.Lstat(directory)
	if err != nil || !os.SameFile(openedInfo, after) {
		return errorf(CodeDenied, "output", "output directory identity changed after publication", err)
	}
	return nil
}
