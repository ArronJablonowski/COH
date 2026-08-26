package nativeexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const maximumArtifactBytes = 1 << 30

type FileArtifactPreparer struct{ root string }

func NewFileArtifactPreparer(root string) (*FileArtifactPreparer, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, NewError(InvalidInput, "artifact_root")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, NewError(Denied, "artifact_root")
	}
	return &FileArtifactPreparer{root: root}, nil
}

func (preparer *FileArtifactPreparer) Prepare(ctx context.Context, sourcePath, expectedDigest string,
	storageLimit uint64) (PreparedArtifact, error) {
	if preparer == nil || preparer.root == "" {
		return PreparedArtifact{}, NewError(Unavailable, "artifact_preparer_unavailable")
	}
	if err := contextError(ctx); err != nil {
		return PreparedArtifact{}, err
	}
	rootInfo, rootErr := os.Lstat(preparer.root)
	if rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
		return PreparedArtifact{}, NewError(Denied, "artifact_root")
	}
	if !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath ||
		!digestPattern.MatchString(expectedDigest) || storageLimit == 0 {
		return PreparedArtifact{}, NewError(InvalidInput, "artifact_request")
	}
	sourceInfo, err := os.Lstat(sourcePath)
	if err != nil || sourceInfo.Mode()&os.ModeSymlink != 0 || !sourceInfo.Mode().IsRegular() ||
		sourceInfo.Mode().Perm()&0o111 == 0 || sourceInfo.Size() <= 0 || sourceInfo.Size() > maximumArtifactBytes ||
		uint64(sourceInfo.Size()) > storageLimit {
		return PreparedArtifact{}, NewError(Denied, "artifact_untrusted")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return PreparedArtifact{}, NewError(Denied, "artifact_untrusted")
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	currentInfo, currentErr := os.Lstat(sourcePath)
	if err != nil || currentErr != nil || currentInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(sourceInfo, openedInfo) || !os.SameFile(openedInfo, currentInfo) {
		return PreparedArtifact{}, NewError(Denied, "artifact_changed")
	}
	directory, err := os.MkdirTemp(preparer.root, "coh-native-artifact-")
	if err != nil {
		return PreparedArtifact{}, NewError(Unavailable, "artifact_stage_unavailable")
	}
	cleanup := func() error { return os.RemoveAll(directory) }
	stagedPath := filepath.Join(directory, "tool")
	staged, err := os.OpenFile(stagedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500)
	if err != nil {
		_ = cleanup()
		return PreparedArtifact{}, NewError(Unavailable, "artifact_stage_unavailable")
	}
	hash := sha256.New()
	written, copyErr := copyContext(ctx, io.MultiWriter(staged, hash), source, storageLimit)
	syncErr := staged.Sync()
	closeErr := staged.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != sourceInfo.Size() {
		_ = cleanup()
		if contextErr := contextError(ctx); contextErr != nil {
			return PreparedArtifact{}, contextErr
		}
		return PreparedArtifact{}, NewError(Unavailable, "artifact_stage_failed")
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if digest != expectedDigest {
		_ = cleanup()
		return PreparedArtifact{}, NewError(Denied, "artifact_digest_mismatch")
	}
	return PreparedArtifact{Path: stagedPath, Digest: digest, Cleanup: cleanup}, nil
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader, limit uint64) (int64, error) {
	buffer := make([]byte, 64*1024)
	var total int64
	for {
		if err := contextError(ctx); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			if uint64(total)+uint64(read) > limit {
				return total, NewError(Denied, "artifact_storage_limit")
			}
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil || written != read {
				return total, errors.Join(writeErr, io.ErrShortWrite)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}
