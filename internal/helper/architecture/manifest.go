package architecture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// WorkspaceSnapshot binds the root module/workspace bytes validated with the
// architecture graph. Future schema versions may add explicitly allowed files.
type WorkspaceSnapshot struct {
	Files []SourceFile
}

// ValidateWorkspaceManifests enforces the module identity and baseline without
// adding x/mod as a bootstrap dependency.
func ValidateWorkspaceManifests(ctx context.Context, root string) (WorkspaceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return WorkspaceSnapshot{}, contractError(CodeCanceled, "workspace", "manifest validation canceled", err)
	}
	modData, modRecord, err := readManifest(root, "go.mod")
	if err != nil {
		return WorkspaceSnapshot{}, err
	}
	workData, workRecord, err := readManifest(root, "go.work")
	if err != nil {
		return WorkspaceSnapshot{}, err
	}
	if err := validateGoMod(modData); err != nil {
		return WorkspaceSnapshot{}, err
	}
	if err := validateGoWork(workData); err != nil {
		return WorkspaceSnapshot{}, err
	}
	return WorkspaceSnapshot{Files: []SourceFile{modRecord, workRecord}}, nil
}

func readManifest(root, name string) ([]byte, SourceFile, error) {
	path := filepath.Join(root, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, SourceFile{}, contractError(CodeInvalidInput, name, "required manifest is unavailable", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, SourceFile{}, contractError(CodeDenied, name, "manifest must be a regular non-symlink file", nil)
	}
	if info.Size() > MaximumContractSize {
		return nil, SourceFile{}, contractError(CodeInvalidInput, name, "manifest exceeds 1 MiB", nil)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, SourceFile{}, contractError(CodeToolFailure, name, "cannot read manifest", err)
	}
	digest := sha256.Sum256(data)
	return data, SourceFile{Path: name, Length: len(data), Digest: hex.EncodeToString(digest[:])}, nil
}

func validateGoMod(data []byte) error {
	state := manifestState{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), MaximumContractSize)
	block := ""
	for scanner.Scan() {
		line := cleanManifestLine(scanner.Text())
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "module":
			if len(fields) != 2 || fields[1] != ModulePath || state.module {
				return contractError(CodeDenied, "go.mod", "module directive must equal "+ModulePath, nil)
			}
			state.module = true
		case "go":
			if len(fields) != 2 || fields[1] != BaselineGoVersion || state.goVersion {
				return contractError(CodeUnsupportedVersion, "go.mod", "go directive must equal "+BaselineGoVersion, nil)
			}
			state.goVersion = true
		case "toolchain":
			if len(fields) != 2 || fields[1] != "go"+BaselineGoVersion || state.toolchain {
				return contractError(CodeUnsupportedVersion, "go.mod", "toolchain directive must equal go"+BaselineGoVersion, nil)
			}
			state.toolchain = true
		case "replace":
			return contractError(CodeDenied, "go.mod", "replace directives require a future reviewed contract", nil)
		case "require", "exclude", "retract":
			if len(fields) == 2 && fields[1] == "(" {
				block = fields[0]
			}
		default:
			return contractError(CodeInvalidInput, "go.mod", "unsupported directive: "+fields[0], nil)
		}
	}
	if err := scanner.Err(); err != nil {
		return contractError(CodeToolFailure, "go.mod", "cannot parse manifest", err)
	}
	if block != "" || !state.module || !state.goVersion || !state.toolchain {
		return contractError(CodeInvalidInput, "go.mod", "required directives are missing or a block is unterminated", nil)
	}
	return nil
}

func validateGoWork(data []byte) error {
	state := manifestState{}
	useCount := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), MaximumContractSize)
	inUseBlock := false
	for scanner.Scan() {
		line := cleanManifestLine(scanner.Text())
		if line == "" {
			continue
		}
		if inUseBlock {
			if line == ")" {
				inUseBlock = false
				continue
			}
			if line != "." {
				return contractError(CodeDenied, "go.work", "only use . is permitted", nil)
			}
			useCount++
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "go":
			if len(fields) != 2 || fields[1] != BaselineGoVersion || state.goVersion {
				return contractError(CodeUnsupportedVersion, "go.work", "go directive must equal "+BaselineGoVersion, nil)
			}
			state.goVersion = true
		case "toolchain":
			if len(fields) != 2 || fields[1] != "go"+BaselineGoVersion || state.toolchain {
				return contractError(CodeUnsupportedVersion, "go.work", "toolchain directive must equal go"+BaselineGoVersion, nil)
			}
			state.toolchain = true
		case "use":
			if len(fields) == 2 && fields[1] == "(" {
				inUseBlock = true
			} else if len(fields) == 2 && fields[1] == "." {
				useCount++
			} else {
				return contractError(CodeDenied, "go.work", "only use . is permitted", nil)
			}
		case "replace":
			return contractError(CodeDenied, "go.work", "replace directives are forbidden", nil)
		default:
			return contractError(CodeInvalidInput, "go.work", "unsupported directive: "+fields[0], nil)
		}
	}
	if err := scanner.Err(); err != nil {
		return contractError(CodeToolFailure, "go.work", "cannot parse manifest", err)
	}
	if inUseBlock || !state.goVersion || !state.toolchain || useCount != 1 {
		return contractError(CodeInvalidInput, "go.work", "exactly one use . and baseline directives are required", nil)
	}
	return nil
}

type manifestState struct {
	module    bool
	goVersion bool
	toolchain bool
}

func cleanManifestLine(line string) string {
	line = strings.TrimSpace(line)
	if index := strings.Index(line, "//"); index >= 0 {
		line = strings.TrimSpace(line[:index])
	}
	return line
}
