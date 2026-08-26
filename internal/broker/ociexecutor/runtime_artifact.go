package ociexecutor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func privateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return NewError(Denied, "runtime_state_root")
	}
	return nil
}

func verifySocket(socket string) error {
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return NewError(Unavailable, "runtime_socket_unavailable")
	}
	return nil
}

func verifyRuntimeFile(path, expected string) error {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o111 == 0 || before.Size() <= 0 || before.Size() > maximumRuntimeBytes {
		return NewError(Denied, "runtime_binary")
	}
	file, err := os.Open(path)
	if err != nil {
		return NewError(Unavailable, "runtime_binary_unavailable")
	}
	hash := sha256.New()
	_, copyErr := io.CopyN(hash, file, maximumRuntimeBytes+1)
	after, statErr := file.Stat()
	closeErr := file.Close()
	if copyErr != nil && !errors.Is(copyErr, io.EOF) || statErr != nil || closeErr != nil || !os.SameFile(before, after) ||
		after.Size() != before.Size() || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected {
		return NewError(Denied, "runtime_binary_digest")
	}
	return nil
}

func stageRuntimeFile(source, expected, stateRoot string) (string, error) {
	if err := verifyRuntimeFile(source, expected); err != nil {
		return "", err
	}
	target := filepath.Join(stateRoot, "docker-runtime-"+strings.TrimPrefix(expected, "sha256:")[:16])
	if _, err := os.Lstat(target); err == nil {
		if err := verifyStagedRuntime(target, expected); err != nil {
			return "", err
		}
		return target, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", NewError(Unavailable, "runtime_stage_unavailable")
	}
	input, err := os.Open(source)
	if err != nil {
		return "", NewError(Unavailable, "runtime_binary_unavailable")
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		_ = input.Close()
		if errors.Is(err, os.ErrExist) && verifyStagedRuntime(target, expected) == nil {
			return target, nil
		}
		return "", NewError(Unavailable, "runtime_stage_unavailable")
	}
	_, copyErr := io.CopyN(output, input, maximumRuntimeBytes+1)
	syncErr := output.Sync()
	outputCloseErr := output.Close()
	inputCloseErr := input.Close()
	if copyErr != nil && !errors.Is(copyErr, io.EOF) || syncErr != nil || outputCloseErr != nil || inputCloseErr != nil {
		_ = os.Remove(target)
		return "", NewError(Unavailable, "runtime_stage_failed")
	}
	if err := verifyStagedRuntime(target, expected); err != nil {
		_ = os.Remove(target)
		return "", err
	}
	return target, nil
}

func verifyStagedRuntime(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o500 {
		return NewError(Denied, "runtime_stage_permissions")
	}
	return verifyRuntimeFile(path, expected)
}
