package filesize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

type Source interface {
	Snapshot(context.Context, string) (Snapshot, error)
	Read(context.Context, string, FileRecord) ([]byte, error)
}

type OSSource struct{}

func (OSSource) Snapshot(ctx context.Context, root string) (Snapshot, error) {
	resolvedRoot, err := resolveRoot(root)
	if err != nil {
		return Snapshot{}, err
	}
	output, err := runGit(ctx, resolvedRoot, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--")
	if err != nil {
		return Snapshot{}, err
	}
	paths, err := splitGitPaths(output)
	if err != nil {
		return Snapshot{}, err
	}
	records := make([]FileRecord, 0, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, contextError(err, "source")
		}
		record, _, err := readStableFile(resolvedRoot, path)
		if err != nil {
			return Snapshot{}, err
		}
		records = append(records, record)
	}
	revision, modified, err := gitState(ctx, resolvedRoot)
	if err != nil {
		return Snapshot{}, err
	}
	canonical, err := json.Marshal(records)
	if err != nil {
		return Snapshot{}, contractError(CodeToolFailure, "source", "cannot canonicalize source records", err)
	}
	return Snapshot{
		Digest: digestBytes(canonical), FileCount: len(records), Records: records,
		VCSRevision: revision, VCSModified: modified,
	}, nil
}

func (OSSource) Read(ctx context.Context, root string, expected FileRecord) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, contextError(err, "source."+expected.Path)
	}
	resolvedRoot, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}
	actual, data, err := readStableFile(resolvedRoot, expected.Path)
	if err != nil {
		return nil, err
	}
	if actual != expected {
		return nil, contractError(CodeDenied, "source."+expected.Path, "file identity or content changed during evaluation", nil)
	}
	return data, nil
}

func resolveRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", contractError(CodeInvalidInput, "root", "cannot resolve repository root", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", contractError(CodeInvalidInput, "root", "root must be a real directory", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", contractError(CodeInvalidInput, "root", "cannot canonicalize repository root", err)
	}
	gitInfo, gitErr := os.Lstat(filepath.Join(resolved, ".git"))
	if gitErr != nil || !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return "", contractError(CodeInvalidInput, "root", "root must contain a real .git directory", gitErr)
	}
	return resolved, nil
}

func splitGitPaths(data []byte) ([]string, error) {
	if len(data) > MaximumInputSize {
		return nil, contractError(CodeDenied, "source", "Git path inventory exceeds 8 MiB", nil)
	}
	if len(data) == 0 {
		return nil, contractError(CodeDenied, "source", "Git path inventory is empty", nil)
	}
	if data[len(data)-1] != 0 {
		return nil, contractError(CodeToolFailure, "source", "Git path inventory is truncated", nil)
	}
	raw := bytes.Split(data[:len(data)-1], []byte{0})
	if len(raw) > MaximumFileCount {
		return nil, contractError(CodeDenied, "source", "Git path inventory exceeds 100000 files", nil)
	}
	paths := make([]string, len(raw))
	for index, item := range raw {
		if !utf8.Valid(item) {
			return nil, contractError(CodeDenied, "source", "Git returned a non-UTF-8 path", nil)
		}
		path := string(item)
		if !safeSourcePath(path) {
			return nil, contractError(CodeDenied, "source", "Git returned an unsafe path", nil)
		}
		paths[index] = path
	}
	slices.Sort(paths)
	for index := 1; index < len(paths); index++ {
		if paths[index-1] == paths[index] {
			return nil, contractError(CodeDenied, "source", "Git returned a duplicate path", nil)
		}
	}
	return paths, nil
}

func safeSourcePath(path string) bool {
	if path == "" || len(path) > MaximumPathSize || !utf8.ValidString(path) || strings.ContainsRune(path, 0) || filepath.IsAbs(filepath.FromSlash(path)) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return clean == path && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func safeIdentity(identity string) bool {
	if identity == "" || len(identity) > MaximumIdentitySize || !utf8.ValidString(identity) {
		return false
	}
	for _, character := range identity {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func realParent(root, relative string) (string, error) {
	parentRelative := filepath.Dir(filepath.FromSlash(relative))
	if parentRelative == "." {
		return root, nil
	}
	current := root
	for _, component := range strings.Split(parentRelative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", contractError(CodeDenied, "source."+relative, "source parent must contain only real directories", err)
		}
	}
	return current, nil
}

func readStableFile(root, relative string) (FileRecord, []byte, error) {
	if !safeSourcePath(relative) {
		return FileRecord{}, nil, contractError(CodeDenied, "source", "unsafe repository path", nil)
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	parent, err := realParent(root, relative)
	if err != nil || !pathWithin(root, parent) {
		return FileRecord{}, nil, contractError(CodeDenied, "source."+relative, "parent is not a real repository directory", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return FileRecord{}, nil, contractError(CodeToolFailure, "source."+relative, "cannot stat source file", err)
	}
	if !before.Mode().IsRegular() || before.Size() > MaximumInputSize {
		return FileRecord{}, nil, contractError(CodeDenied, "source."+relative, "source must be a regular file of at most 8 MiB", nil)
	}
	file, err := os.Open(path)
	if err != nil {
		return FileRecord{}, nil, contractError(CodeToolFailure, "source."+relative, "cannot open source file", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaximumInputSize+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil {
		return FileRecord{}, nil, contractError(CodeToolFailure, "source."+relative, "cannot read source file", errors.Join(readErr, statErr, closeErr))
	}
	final, err := os.Lstat(path)
	finalParent, parentErr := realParent(root, relative)
	if err != nil || parentErr != nil || finalParent != parent || !pathWithin(root, finalParent) ||
		!os.SameFile(before, after) || !os.SameFile(after, final) ||
		before.Mode() != after.Mode() || after.Mode() != final.Mode() ||
		before.Size() != after.Size() || after.Size() != final.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(final.ModTime()) ||
		len(data) > MaximumInputSize || int64(len(data)) != final.Size() {
		return FileRecord{}, nil, contractError(CodeDenied, "source."+relative, "source changed or exceeded limits while read", errors.Join(err, parentErr))
	}
	identity, identityErr := fileIdentity(final)
	if identityErr != nil {
		return FileRecord{}, nil, contractError(CodeToolFailure, "source."+relative, "cannot bind source identity", identityErr)
	}
	record := FileRecord{
		Path: relative, Length: int64(len(data)), Executable: final.Mode()&0o111 != 0,
		SHA256: digestBytes(data), Mode: uint32(final.Mode()), Identity: identity,
	}
	return record, data, nil
}

func gitState(ctx context.Context, root string) (string, bool, error) {
	revisionData, revisionErr := runGit(ctx, root, "rev-parse", "--verify", "HEAD")
	revision := strings.TrimSpace(string(revisionData))
	if revisionErr != nil {
		if code := CodeOf(revisionErr); code == CodeCanceled || code == CodeTimeout {
			return "", false, revisionErr
		}
		anyRevision, err := runGit(ctx, root, "rev-list", "--all", "--max-count=1")
		if err != nil || len(bytes.TrimSpace(anyRevision)) != 0 {
			return "", false, contractError(CodeToolFailure, "git", "cannot resolve repository revision", revisionErr)
		}
		revision = "unborn"
	}
	status, err := runGit(ctx, root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return "", false, err
	}
	return revision, len(status) != 0, nil
}

func runGit(ctx context.Context, root string, arguments ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, contextError(err, "git")
	}
	gitDirectory := filepath.Join(root, ".git")
	gitInfo, gitErr := os.Lstat(gitDirectory)
	if gitErr != nil || !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return nil, contractError(CodeInvalidInput, "git", "repository metadata must be a real directory", gitErr)
	}
	commandArguments := []string{
		"--git-dir=" + gitDirectory, "--work-tree=" + root,
		"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
	}
	commandArguments = append(commandArguments, arguments...)
	command := exec.CommandContext(ctx, "/usr/bin/git", commandArguments...)
	command.Dir = root
	command.Env = []string{
		"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C",
	}
	stdout := &limitBuffer{limit: MaximumInputSize}
	stderr := &limitBuffer{limit: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, contextError(ctx.Err(), "git")
		}
		if errors.Is(err, errLimitExceeded) {
			return nil, contractError(CodeDenied, "git", "Git output exceeds its bound", err)
		}
		return nil, contractError(CodeToolFailure, "git", "Git command failed", err)
	}
	return stdout.Bytes(), nil
}

var errLimitExceeded = errors.New("output limit exceeded")

type limitBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *limitBuffer) Write(data []byte) (int, error) {
	if buffer.Len()+len(data) > buffer.limit {
		remaining := buffer.limit - buffer.Len()
		if remaining > 0 {
			_, _ = buffer.Buffer.Write(data[:remaining])
		}
		return len(data), errLimitExceeded
	}
	return buffer.Buffer.Write(data)
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
