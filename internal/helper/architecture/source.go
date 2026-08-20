package architecture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	maximumWorkspaceFiles = 100_000
	maximumSourceSize     = 8 << 20
	maximumFileListOutput = 32 << 20
)

// ValidateWorkspaceLayout rejects nested modules and workspaces within the
// tracked or non-ignored source set. Ignored/generated files are not product
// source; the active go-list graph still denies imports from them.
func ValidateWorkspaceLayout(ctx context.Context, root string) error {
	files, err := workspaceFiles(ctx, root)
	if err != nil {
		return err
	}
	foundModule, foundWorkspace := false, false
	for _, relative := range files {
		name := filepath.Base(relative)
		if name != "go.mod" && name != "go.work" {
			continue
		}
		if filepath.Dir(relative) != "." {
			return contractError(CodeDenied, "workspace", "nested "+name+" is forbidden: "+filepath.ToSlash(relative), nil)
		}
		if name == "go.mod" {
			foundModule = true
		} else {
			foundWorkspace = true
		}
	}
	if !foundModule || !foundWorkspace {
		return contractError(CodeInvalidInput, "workspace", "root go.mod and go.work are required", nil)
	}
	return nil
}

// ScanSourcePackages parses imports and hashes the same byte buffer for every
// Go source file, independent of active GOOS, GOARCH, or build tags.
func ScanSourcePackages(ctx context.Context, root, module string) ([]Package, error) {
	files, err := workspaceFiles(ctx, root)
	if err != nil {
		return nil, err
	}
	packages := make(map[string]*Package)
	for _, relative := range files {
		if filepath.Ext(relative) != ".go" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, contractError(CodeCanceled, "workspace", "source scan canceled", err)
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil {
			return nil, contractError(CodeToolFailure, "workspace", "cannot stat Go source", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, contractError(CodeDenied, "workspace", "symlinked Go source is forbidden: "+relative, nil)
		}
		if info.Size() > maximumSourceSize {
			return nil, contractError(CodeInvalidInput, "workspace", "Go source file exceeds 8 MiB", nil)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, contractError(CodeToolFailure, "workspace", "cannot read Go source", err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), relative, data, parser.ImportsOnly)
		if err != nil {
			return nil, contractError(CodeToolFailure, "workspace", "cannot parse Go imports: "+relative, err)
		}
		directory := filepath.ToSlash(filepath.Dir(relative))
		importPath := module
		if directory != "." {
			importPath += "/" + directory
		}
		pkg := packages[importPath]
		if pkg == nil {
			pkg = &Package{ImportPath: importPath}
			packages[importPath] = pkg
		}
		digest := sha256.Sum256(data)
		pkg.SourceFiles = append(pkg.SourceFiles, SourceFile{
			Path: filepath.ToSlash(relative), Length: len(data), Digest: hex.EncodeToString(digest[:]),
		})
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return nil, contractError(CodeToolFailure, "workspace", "cannot decode Go import", err)
			}
			pkg.Imports = append(pkg.Imports, value)
		}
	}
	result := make([]Package, 0, len(packages))
	for _, pkg := range packages {
		pkg.Imports = deduplicate(pkg.Imports)
		pkg.SourceFiles = deduplicateSources(pkg.SourceFiles)
		result = append(result, *pkg)
	}
	slices.SortFunc(result, comparePackages)
	return result, nil
}

// MergePackages combines active compiler metadata with the all-source scan.
func MergePackages(listed, scanned []Package) []Package {
	merged := make(map[string]Package, len(listed)+len(scanned))
	for _, pkg := range append(slices.Clone(listed), scanned...) {
		current := merged[pkg.ImportPath]
		current.ImportPath = pkg.ImportPath
		current.Imports = append(current.Imports, pkg.Imports...)
		current.TestImports = append(current.TestImports, pkg.TestImports...)
		current.XTestImports = append(current.XTestImports, pkg.XTestImports...)
		current.SourceFiles = append(current.SourceFiles, pkg.SourceFiles...)
		merged[pkg.ImportPath] = current
	}
	result := make([]Package, 0, len(merged))
	for _, pkg := range merged {
		pkg.Imports = deduplicate(pkg.Imports)
		pkg.TestImports = deduplicate(pkg.TestImports)
		pkg.XTestImports = deduplicate(pkg.XTestImports)
		pkg.SourceFiles = deduplicateSources(pkg.SourceFiles)
		result = append(result, pkg)
	}
	slices.SortFunc(result, comparePackages)
	return result
}

// DigestSources hashes Go-source and workspace-manifest records created from
// the same buffers used for validation and import parsing.
func DigestSources(ctx context.Context, packages []Package, manifests WorkspaceSnapshot) (string, int, error) {
	records, err := sourceRecords(ctx, packages, manifests.Files)
	if err != nil {
		return "", 0, err
	}
	canonical, err := json.Marshal(records)
	if err != nil {
		return "", 0, contractError(CodeToolFailure, "sources", "cannot encode source manifest", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), len(records), nil
}

// VerifyWorkspaceSnapshot rescans the complete source set and manifests. It
// detects changed, removed, and newly added files before evidence is emitted.
func VerifyWorkspaceSnapshot(
	ctx context.Context,
	root, module string,
	packages []Package,
	manifests WorkspaceSnapshot,
) error {
	expected, err := sourceRecords(ctx, packages, manifests.Files)
	if err != nil {
		return err
	}
	currentPackages, err := ScanSourcePackages(ctx, root, module)
	if err != nil {
		return err
	}
	currentManifests, err := ValidateWorkspaceManifests(ctx, root)
	if err != nil {
		return err
	}
	current, err := sourceRecords(ctx, currentPackages, currentManifests.Files)
	if err != nil {
		return err
	}
	if !slices.Equal(expected, current) {
		return contractError(CodeDenied, "sources", "workspace source set changed after scan", nil)
	}
	return nil
}

func sourceRecords(ctx context.Context, packages []Package, additional []SourceFile) ([]SourceFile, error) {
	byPath := make(map[string]SourceFile)
	for _, pkg := range packages {
		for _, record := range pkg.SourceFiles {
			if err := ctx.Err(); err != nil {
				return nil, contractError(CodeCanceled, "sources", "source manifest canceled", err)
			}
			if previous, duplicate := byPath[record.Path]; duplicate && previous != record {
				return nil, contractError(CodeInvalidInput, "sources", "conflicting source records", nil)
			}
			byPath[record.Path] = record
		}
	}
	for _, record := range additional {
		if previous, duplicate := byPath[record.Path]; duplicate && previous != record {
			return nil, contractError(CodeInvalidInput, "sources", "conflicting input records", nil)
		}
		byPath[record.Path] = record
	}
	if len(byPath) == 0 {
		return nil, contractError(CodeInvalidInput, "sources", "no Go source files found", nil)
	}
	records := make([]SourceFile, 0, len(byPath))
	for _, record := range byPath {
		records = append(records, record)
	}
	slices.SortFunc(records, func(a, b SourceFile) int { return strings.Compare(a.Path, b.Path) })
	return records, nil
}

func workspaceFiles(ctx context.Context, root string) ([]string, error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		files, err := gitWorkspaceFiles(ctx, root)
		if err != nil {
			return nil, err
		}
		protected, err := protectedBoundaryFiles(ctx, root)
		if err != nil {
			return nil, err
		}
		return validateFileList(append(files, protected...))
	}
	return walkedWorkspaceFiles(ctx, root)
}

func protectedBoundaryFiles(ctx context.Context, root string) ([]string, error) {
	files := make([]string, 0, 128)
	for _, directory := range []string{"cmd", "internal"} {
		base := filepath.Join(root, directory)
		if _, err := os.Stat(base); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, contractError(CodeToolFailure, "workspace", "cannot inspect boundary root", err)
		}
		err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() && entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if filepath.Ext(name) != ".go" && name != "go.mod" && name != "go.work" {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(relative))
			return nil
		})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, contractError(CodeCanceled, "workspace", "boundary scan canceled", ctxErr)
			}
			return nil, contractError(CodeToolFailure, "workspace", "boundary scan failed", err)
		}
	}
	return files, nil
}

func gitWorkspaceFiles(ctx context.Context, root string) ([]string, error) {
	command := exec.CommandContext(ctx, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	command.Dir = root
	var output limitedBuffer
	output.remaining = maximumFileListOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, contractError(CodeCanceled, "workspace", "file discovery canceled", ctxErr)
		}
		return nil, contractError(CodeToolFailure, "workspace", "git file discovery failed", err)
	}
	parts := bytes.Split(output.Bytes(), []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		files = append(files, filepath.ToSlash(string(part)))
	}
	return validateFileList(files)
}

func walkedWorkspaceFiles(ctx context.Context, root string) ([]string, error) {
	files := make([]string, 0, 128)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() && path != root && skippedSourceDirectory(entry.Name()) {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, contractError(CodeCanceled, "workspace", "file discovery canceled", ctxErr)
		}
		return nil, contractError(CodeToolFailure, "workspace", "file discovery failed", err)
	}
	return validateFileList(files)
}

func validateFileList(files []string) ([]string, error) {
	if len(files) > maximumWorkspaceFiles {
		return nil, contractError(CodeInvalidInput, "workspace", "workspace file limit exceeded", nil)
	}
	for _, relative := range files {
		clean := filepath.Clean(filepath.FromSlash(relative))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, contractError(CodeDenied, "workspace", "file path escapes workspace", nil)
		}
	}
	slices.Sort(files)
	return slices.Compact(files), nil
}

func deduplicate(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

func deduplicateSources(records []SourceFile) []SourceFile {
	slices.SortFunc(records, func(a, b SourceFile) int { return strings.Compare(a.Path, b.Path) })
	return slices.CompactFunc(records, func(a, b SourceFile) bool { return a == b })
}

func comparePackages(a, b Package) int { return strings.Compare(a.ImportPath, b.ImportPath) }

func skippedSourceDirectory(name string) bool {
	return name == ".git" || name == "bin" || name == "coverage" || name == "dist" ||
		name == "node_modules" || name == "testdata" || name == "tmp" || name == "work" ||
		strings.HasPrefix(name, ".internal-mirror-backup-")
}
