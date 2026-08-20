package quality

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// FuzzTarget is one deterministic seed-only fuzz gate registration.
type FuzzTarget struct {
	Package string
	Name    string
}

// VerifyFuzzManifest parses Go syntax, requires at least one direct seed call
// per fuzz function, and enforces equality with the closed target manifest.
func VerifyFuzzManifest(ctx context.Context, root, manifestPath string) ([]FuzzTarget, error) {
	manifest, err := parseFuzzManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	discovered, err := discoverFuzzTargets(ctx, root)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(manifest, discovered) {
		return nil, qualityError(CodeDenied, "fuzz_manifest", "registered targets do not exactly match source targets", nil)
	}
	return manifest, nil
}

func parseFuzzManifest(manifestPath string) ([]FuzzTarget, error) {
	data, err := readBoundedRegular(manifestPath, MaximumPolicySize)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), MaximumPolicySize)
	var targets []FuzzTarget
	seen := make(map[string]struct{})
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !validFuzzPackage(fields[0]) || !validFuzzName(fields[1]) {
			return nil, qualityError(CodeInvalidInput, "fuzz_manifest", "invalid row at line "+strconv.Itoa(lineNumber), nil)
		}
		target := FuzzTarget{Package: fields[0], Name: fields[1]}
		key := target.Package + " " + target.Name
		if _, duplicate := seen[key]; duplicate {
			return nil, qualityError(CodeInvalidInput, "fuzz_manifest", "duplicate target", nil)
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	if err := scanner.Err(); err != nil {
		return nil, qualityError(CodeInvalidInput, "fuzz_manifest", "cannot scan manifest", err)
	}
	if len(targets) == 0 {
		return nil, qualityError(CodeDenied, "fuzz_manifest", "at least one fuzz target is required", nil)
	}
	if !slices.IsSortedFunc(targets, compareFuzzTargets) {
		return nil, qualityError(CodeInvalidInput, "fuzz_manifest", "targets must be in canonical order", nil)
	}
	return targets, nil
}

func discoverFuzzTargets(ctx context.Context, root string) ([]FuzzTarget, error) {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return nil, qualityError(CodeInvalidInput, "fuzz_source", "invalid root", err)
	}
	var targets []FuzzTarget
	err = filepath.WalkDir(rootPath, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return qualityError(CodeToolFailure, "fuzz_source", "cannot walk source", walkErr)
		}
		if err := ctx.Err(); err != nil {
			return contextQualityError(err, "fuzz_source")
		}
		if entry.IsDir() {
			if filePath != rootPath && excludedFuzzDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maximumArtifactSize {
			return qualityError(CodeDenied, "fuzz_source", "test source must be a bounded regular file", err)
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return qualityError(CodeToolFailure, "fuzz_source", "cannot read test source", err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filePath, data, 0)
		if err != nil {
			return qualityError(CodeDenied, "fuzz_source", "cannot parse test source", err)
		}
		matched, err := build.Default.MatchFile(filepath.Dir(filePath), entry.Name())
		if err != nil {
			return qualityError(CodeDenied, "fuzz_source", "cannot evaluate build constraints", err)
		}
		packageName, err := fuzzPackage(rootPath, filepath.Dir(filePath))
		if err != nil {
			return err
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "Fuzz") {
				continue
			}
			if !matched {
				return qualityError(CodeDenied, "fuzz_source", "fuzz target is inactive on this platform", nil)
			}
			parameter, ok := fuzzParameter(function)
			if !ok || !validFuzzName(function.Name.Name) {
				return qualityError(CodeDenied, "fuzz_source", "fuzz target has a noncanonical signature", nil)
			}
			if !hasCanonicalSeedRegistration(function.Body, parameter) {
				return qualityError(CodeDenied, "fuzz_source", "fuzz target must directly register a seed before its callback", nil)
			}
			targets = append(targets, FuzzTarget{Package: packageName, Name: function.Name.Name})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(targets, compareFuzzTargets)
	for index := 1; index < len(targets); index++ {
		if targets[index] == targets[index-1] {
			return nil, qualityError(CodeDenied, "fuzz_source", "duplicate fuzz target", nil)
		}
	}
	return targets, nil
}

func fuzzParameter(function *ast.FuncDecl) (string, bool) {
	if function.Type.Results != nil || function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return "", false
	}
	field := function.Type.Params.List[0]
	if len(field.Names) != 1 {
		return "", false
	}
	pointer, ok := field.Type.(*ast.StarExpr)
	if !ok {
		return "", false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	packageIdentifier, packageOK := selector.X.(*ast.Ident)
	return field.Names[0].Name, packageOK && packageIdentifier.Name == "testing" && selector.Sel.Name == "F"
}

func hasCanonicalSeedRegistration(body *ast.BlockStmt, parameter string) bool {
	if fuzzParameterRebound(body, parameter) {
		return false
	}
	seedCount, callbackSeen := 0, false
	for _, statement := range body.List {
		call, method, direct := directFuzzCall(statement, parameter)
		if direct {
			switch method {
			case "Add":
				if callbackSeen || len(call.Args) == 0 {
					return false
				}
				seedCount++
			case "Fuzz":
				_, literal := firstCallArgument(call).(*ast.FuncLit)
				if callbackSeen || seedCount == 0 || len(call.Args) != 1 || !literal {
					return false
				}
				callbackSeen = true
			}
		}
		if containsNoncanonicalFuzzCall(statement, parameter, call) {
			return false
		}
	}
	return seedCount > 0 && callbackSeen
}

func directFuzzCall(statement ast.Stmt, parameter string) (*ast.CallExpr, string, bool) {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return nil, "", false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok {
		return nil, "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, "", false
	}
	receiver, receiverOK := selector.X.(*ast.Ident)
	if !receiverOK || receiver.Name != parameter || (selector.Sel.Name != "Add" && selector.Sel.Name != "Fuzz") {
		return nil, "", false
	}
	return call, selector.Sel.Name, true
}

func containsNoncanonicalFuzzCall(statement ast.Stmt, parameter string, allowed *ast.CallExpr) bool {
	invalid := false
	ast.Inspect(statement, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || call == allowed {
			return !invalid
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return !invalid
		}
		receiver, receiverOK := selector.X.(*ast.Ident)
		if receiverOK && receiver.Name == parameter && (selector.Sel.Name == "Add" || selector.Sel.Name == "Fuzz") {
			invalid = true
			return false
		}
		return !invalid
	})
	return invalid
}

func fuzzParameterRebound(body *ast.BlockStmt, parameter string) bool {
	rebound := false
	ast.Inspect(body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.AssignStmt:
			for _, expression := range typed.Lhs {
				if identifier, ok := expression.(*ast.Ident); ok && identifier.Name == parameter {
					rebound = true
				}
			}
		case *ast.ValueSpec:
			for _, identifier := range typed.Names {
				if identifier.Name == parameter {
					rebound = true
				}
			}
		case *ast.FuncLit:
			if fieldListNames(typed.Type.Params, parameter) {
				rebound = true
			}
		}
		return !rebound
	})
	return rebound
}

func fieldListNames(fields *ast.FieldList, name string) bool {
	if fields == nil {
		return false
	}
	for _, field := range fields.List {
		for _, identifier := range field.Names {
			if identifier.Name == name {
				return true
			}
		}
	}
	return false
}

func firstCallArgument(call *ast.CallExpr) ast.Expr {
	if len(call.Args) == 0 {
		return nil
	}
	return call.Args[0]
}

// VerifyFuzzExecution accepts only a real go test -json trajectory containing
// at least one run-and-pass seed callback before the target passes.
func VerifyFuzzExecution(ctx context.Context, tracePath, target string) (int, error) {
	if !validFuzzName(target) {
		return 0, qualityError(CodeInvalidInput, "fuzz_execution", "invalid fuzz target", nil)
	}
	data, err := readBoundedRegular(tracePath, maximumArtifactSize)
	if err != nil {
		return 0, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	seedRuns, seedPasses := make(map[string]bool), make(map[string]bool)
	targetRun, targetPass := false, false
	for {
		if err := ctx.Err(); err != nil {
			return 0, contextQualityError(err, "fuzz_execution")
		}
		var event struct {
			Action string `json:"Action"`
			Test   string `json:"Test"`
		}
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return 0, qualityError(CodeDenied, "fuzz_execution", "invalid go test JSON trace", err)
		}
		switch {
		case event.Test == target && event.Action == "run":
			if targetRun || targetPass {
				return 0, qualityError(CodeDenied, "fuzz_execution", "duplicate target execution", nil)
			}
			targetRun = true
		case strings.HasPrefix(event.Test, target+"/seed#") && event.Action == "run":
			if !targetRun || targetPass || seedRuns[event.Test] {
				return 0, qualityError(CodeDenied, "fuzz_execution", "invalid seed execution order", nil)
			}
			seedRuns[event.Test] = true
		case strings.HasPrefix(event.Test, target+"/seed#") && event.Action == "pass":
			if !seedRuns[event.Test] || seedPasses[event.Test] {
				return 0, qualityError(CodeDenied, "fuzz_execution", "seed passed without one execution", nil)
			}
			seedPasses[event.Test] = true
		case event.Test == target && event.Action == "pass":
			if !targetRun || targetPass || len(seedPasses) == 0 {
				return 0, qualityError(CodeDenied, "fuzz_execution", "target passed without a seed callback", nil)
			}
			targetPass = true
		case (event.Test == target || strings.HasPrefix(event.Test, target+"/seed#")) && event.Action == "fail":
			return 0, qualityError(CodeDenied, "fuzz_execution", "fuzz target or seed failed", nil)
		}
	}
	if !targetPass || len(seedRuns) != len(seedPasses) {
		return 0, qualityError(CodeDenied, "fuzz_execution", "seed execution proof is incomplete", nil)
	}
	return len(seedPasses), nil
}

func validFuzzPackage(value string) bool {
	if !strings.HasPrefix(value, "./") || strings.Contains(value, "\\") {
		return false
	}
	relative := strings.TrimPrefix(value, "./")
	return relative != "" && relative != "." && !strings.HasPrefix(relative, "/") && path.Clean(relative) == relative && relative != ".." && !strings.HasPrefix(relative, "../")
}

func validFuzzName(value string) bool {
	if len(value) <= len("Fuzz") || !strings.HasPrefix(value, "Fuzz") {
		return false
	}
	for _, character := range value[len("Fuzz"):] {
		if character != '_' && !unicode.IsLetter(character) && !unicode.IsDigit(character) {
			return false
		}
	}
	return true
}

func fuzzPackage(root, directory string) (string, error) {
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", qualityError(CodeDenied, "fuzz_source", "fuzz target must be in a module subpackage", err)
	}
	return "./" + filepath.ToSlash(relative), nil
}

func excludedFuzzDirectory(name string) bool {
	switch name {
	case ".git", ".cache", "dist", "node_modules", "vendor", "work":
		return true
	default:
		return false
	}
}

func compareFuzzTargets(left, right FuzzTarget) int {
	return strings.Compare(left.Package+" "+left.Name, right.Package+" "+right.Name)
}
