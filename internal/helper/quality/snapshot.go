package quality

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

const (
	maximumSnapshotFiles = 100_000
	maximumSnapshotBytes = 32 << 20
	maximumInputFile     = 8 << 20
)

// SnapshotWorkspace hashes the complete Git-aware input set. CI evidence is
// external to the repository, so no in-tree path is exempt from integrity
// checking. Discovery and hashing are repeated after all stages.
func SnapshotWorkspace(ctx context.Context, root string) (Snapshot, error) {
	if err := rejectIgnoredActiveInputs(ctx, root); err != nil {
		return Snapshot{}, err
	}
	files, err := gitFiles(ctx, root)
	if err != nil {
		return Snapshot{}, err
	}
	records := make([]fileRecord, 0, len(files))
	for _, relative := range files {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, contextQualityError(err, "snapshot")
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil {
			return Snapshot{}, qualityError(CodeToolFailure, "snapshot", "cannot stat input", err)
		}
		if !info.Mode().IsRegular() || info.Size() > maximumInputFile {
			return Snapshot{}, qualityError(CodeDenied, "snapshot", "input is not a bounded regular file: "+relative, nil)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return Snapshot{}, qualityError(CodeToolFailure, "snapshot", "cannot read input", err)
		}
		sum := sha256.Sum256(data)
		records = append(records, fileRecord{
			Path: relative, Length: len(data), SHA256: hex.EncodeToString(sum[:]),
			Mode: uint32(info.Mode().Perm()),
		})
	}
	slices.SortFunc(records, func(a, b fileRecord) int { return strings.Compare(a.Path, b.Path) })
	canonical, err := json.Marshal(records)
	if err != nil {
		return Snapshot{}, qualityError(CodeToolFailure, "snapshot", "cannot encode input manifest", err)
	}
	sum := sha256.Sum256(canonical)
	revision, modified, err := vcsState(ctx, root)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Digest: hex.EncodeToString(sum[:]), FileCount: len(records), VCSRevision: revision, VCSModified: modified, records: records}, nil
}

func rejectIgnoredActiveInputs(ctx context.Context, root string) error {
	command, err := gitCommand(ctx, root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z")
	if err != nil {
		return err
	}
	var output boundedBuffer
	output.remaining = maximumSnapshotBytes
	command.Stdout = &output
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return contextQualityError(ctxErr, "snapshot")
		}
		return qualityError(CodeToolFailure, "snapshot", "cannot inspect ignored inputs", err)
	}
	for _, part := range bytes.Split(output.Bytes(), []byte{0}) {
		if activeIgnoredPath(filepath.ToSlash(string(part))) {
			return qualityError(CodeDenied, "snapshot", "ignored active input is forbidden: "+string(part), nil)
		}
	}
	return nil
}

func activeIgnoredPath(path string) bool {
	base := filepath.Base(path)
	for _, suffix := range []string{".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".s", ".S", ".syso"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	if slices.Contains([]string{"go.mod", "go.sum", "go.work", "go.work.sum", "staticcheck.conf", ".shellcheckrc", ".gitleaks.toml", ".gitleaksignore", "LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"}, base) {
		return true
	}
	return strings.HasPrefix(path, "scripts/") || strings.HasPrefix(path, "ci/") || strings.HasPrefix(path, ".github/workflows/")
}

func VerifySnapshot(ctx context.Context, root string, expected Snapshot) error {
	actual, err := SnapshotWorkspace(ctx, root)
	if err != nil {
		return err
	}
	if actual.Digest != expected.Digest || !slices.Equal(actual.records, expected.records) ||
		actual.VCSRevision != expected.VCSRevision || actual.VCSModified != expected.VCSModified {
		return qualityError(CodeDenied, "snapshot", "workspace inputs changed during quality evaluation", nil)
	}
	return nil
}

func gitFiles(ctx context.Context, root string) ([]string, error) {
	command, err := gitCommand(ctx, root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	var output boundedBuffer
	output.remaining = maximumSnapshotBytes
	command.Stdout = &output
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, contextQualityError(ctxErr, "snapshot")
		}
		return nil, qualityError(CodeToolFailure, "snapshot", "Git file discovery failed", err)
	}
	parts := bytes.Split(output.Bytes(), []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		relative := filepath.ToSlash(string(part))
		if relative == "." || strings.HasPrefix(relative, "../") || filepath.IsAbs(relative) {
			return nil, qualityError(CodeDenied, "snapshot", "Git returned an unsafe path", nil)
		}
		files = append(files, relative)
		if len(files) > maximumSnapshotFiles {
			return nil, qualityError(CodeDenied, "snapshot", "input count exceeds limit", nil)
		}
	}
	slices.Sort(files)
	return slices.Compact(files), nil
}

func vcsState(ctx context.Context, root string) (string, bool, error) {
	revisionCommand, err := gitCommand(ctx, root, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", false, err
	}
	revisionBytes, revisionErr := revisionCommand.Output()
	revision := strings.TrimSpace(string(revisionBytes))
	if revisionErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(revisionErr, &exitErr) {
			return "", false, qualityError(CodeToolFailure, "vcs", "cannot inspect revision", revisionErr)
		}
		revision = "unborn"
	}
	statusCommand, err := gitCommand(ctx, root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return "", false, err
	}
	status, err := statusCommand.Output()
	if err != nil {
		return "", false, qualityError(CodeToolFailure, "vcs", "cannot inspect status", err)
	}
	return revision, len(bytes.TrimSpace(status)) != 0, nil
}

func gitCommand(ctx context.Context, root string, arguments ...string) (*exec.Cmd, error) {
	const gitPath = "/usr/bin/git"
	info, err := os.Lstat(gitPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return nil, qualityError(CodeToolFailure, "vcs", "trusted Git executable is unavailable", err)
	}
	gitDirectory := filepath.Join(root, ".git")
	fixed := []string{
		"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
		"--git-dir=" + gitDirectory, "--work-tree=" + root,
	}
	fixed = append(fixed, arguments...)
	command := exec.CommandContext(ctx, gitPath, fixed...)
	command.Dir = root
	command.Env = []string{
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_COUNT=0",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_OPTIONAL_LOCKS=0", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin",
	}
	return command, nil
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.remaining {
		return 0, io.ErrShortBuffer
	}
	b.remaining -= len(data)
	return b.buffer.Write(data)
}

func (b *boundedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func contextQualityError(err error, field string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return qualityError(CodeTimeout, field, "deadline exceeded", err)
	}
	return qualityError(CodeCanceled, field, "operation canceled", err)
}
