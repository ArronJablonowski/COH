package filesize

import (
	"errors"
	"os"
	"path/filepath"
)

type atomicPublisher func(temporaryPath, destinationPath string) error

func writeAtomic(path string, data []byte) error {
	return writeAtomicWithPublisher(path, data, publishNoReplace)
}

func publishNoReplace(temporaryPath, destinationPath string) error {
	return os.Link(temporaryPath, destinationPath)
}

func writeAtomicWithPublisher(path string, data []byte, publish atomicPublisher) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return contractError(CodeInvalidInput, "output", "output parent must be a real directory", err)
	}
	temporary, err := os.CreateTemp(directory, ".file-size-report.*.tmp")
	if err != nil {
		return contractError(CodeToolFailure, "output", "cannot create sibling temporary report", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return contractError(CodeToolFailure, "output", "cannot set report mode", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return contractError(CodeToolFailure, "output", "cannot write report", err)
	}
	if err := temporary.Sync(); err != nil {
		return contractError(CodeToolFailure, "output", "cannot sync report", err)
	}
	if err := temporary.Close(); err != nil {
		return contractError(CodeToolFailure, "output", "cannot close report", err)
	}
	if publish == nil {
		return contractError(CodeInvalidInput, "output", "atomic publisher is required", nil)
	}
	if err := publish(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return contractError(CodeDenied, "output", "report output must not already exist", err)
		}
		return contractError(CodeToolFailure, "output", "cannot publish report", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return contractError(CodeToolFailure, "output", "cannot remove linked temporary report", err)
	}
	committed = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return contractError(CodeToolFailure, "output", "cannot open report directory", err)
	}
	syncErr := directoryHandle.Sync()
	closeErr := directoryHandle.Close()
	if syncErr != nil || closeErr != nil {
		return contractError(CodeToolFailure, "output", "cannot sync report directory", errors.Join(syncErr, closeErr))
	}
	return nil
}
