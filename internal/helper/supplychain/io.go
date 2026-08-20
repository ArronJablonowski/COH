package supplychain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func readStableRegular(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum < 1 {
		return nil, errorf(CodeInvalidInput, "path", "bounded file path is required", nil)
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errorf(CodeToolFailure, "path", "cannot inspect input", err)
	}
	if !before.Mode().IsRegular() || before.Size() > maximum {
		return nil, errorf(CodeDenied, "path", "input must be a bounded regular file", nil)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errorf(CodeToolFailure, "path", "cannot open input", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, errorf(CodeDenied, "path", "input identity changed before read", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, errorf(CodeToolFailure, "path", "cannot read input", err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || int64(len(data)) != opened.Size() || int64(len(data)) > maximum {
		return nil, errorf(CodeDenied, "path", "input identity or length changed during read", err)
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return nil, err
	}
	return data, nil
}

func rejectSymlinkAncestors(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errorf(CodeInvalidInput, "path", "cannot resolve input path", err)
	}
	current := filepath.VolumeName(absolute) + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(absolute, current), string(filepath.Separator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				return nil
			}
			return errorf(CodeToolFailure, "path", "cannot inspect path component", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errorf(CodeDenied, "path", "symlink path component is forbidden", nil)
		}
	}
	return nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func artifactFor(path, name string) (Artifact, []byte, error) {
	if filepath.Base(name) != name || name == "." {
		return Artifact{}, nil, errorf(CodeInvalidInput, "artifact", "artifact name must be a basename", nil)
	}
	data, err := readStableRegular(path, MaximumFileSize)
	if err != nil {
		return Artifact{}, nil, err
	}
	sum := sha256.Sum256(data)
	return Artifact{Path: name, SHA256: hex.EncodeToString(sum[:]), Length: int64(len(data))}, data, nil
}

func FileArtifact(path, name string) (Artifact, error) {
	artifact, _, err := artifactFor(path, name)
	return artifact, err
}

// ReadPrivateKey returns a bounded, stable regular-file read suitable for a
// separately provisioned signing key. Callers must never log the returned bytes.
func ReadPrivateKey(path string) ([]byte, error) {
	return readStableRegular(path, 1<<16)
}
