package broker

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const moduleImportPath = "github.com/ArronJablonowski/COH"

var sensitiveImportRoots = []string{
	moduleImportPath + "/internal/connector",
	moduleImportPath + "/internal/policy",
}

var forbiddenCapabilityNames = map[string]bool{
	"Dispatch": true,
	"Evaluate": true,
}

type surfaceFile struct {
	path             string
	syntax           *ast.File
	dotSensitivePath string
}

type surfacePackage struct {
	directory string
	name      string
	files     []*surfaceFile
}

type moduleSourceImporter struct {
	set        *token.FileSet
	moduleRoot string
	cache      map[string]*types.Package
	loading    map[string]bool
	fallback   types.Importer
}

func scanBrokerPublicSurface(root string) ([]string, error) {
	packages, set, err := loadBrokerPackages(root)
	if err != nil {
		return nil, err
	}
	moduleRoot, err := sourceModuleRoot()
	if err != nil {
		return nil, err
	}
	imports := &moduleSourceImporter{
		set: set, moduleRoot: moduleRoot,
		cache:    make(map[string]*types.Package),
		loading:  make(map[string]bool),
		fallback: importer.Default(),
	}
	var violations []string
	for _, pkg := range packages {
		info := &types.Info{Defs: make(map[*ast.Ident]types.Object)}
		config := types.Config{Importer: imports, IgnoreFuncBodies: true}
		typed, err := config.Check(surfaceImportPath(root, pkg.directory), set, syntaxFiles(pkg.files), info)
		if err != nil {
			return nil, fmt.Errorf("type-check broker package %s: %w", pkg.directory, err)
		}
		violations = append(violations, pkg.publicSurfaceViolations(typed, info)...)
	}
	sort.Strings(violations)
	return uniqueStrings(violations), nil
}

func sourceModuleRoot() (string, error) {
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate broker surface checker source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", ".."))
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read module contract: %w", err)
	}
	if !strings.HasPrefix(string(module), "module "+moduleImportPath+"\n") {
		return "", fmt.Errorf("module path differs from locked broker surface contract")
	}
	return root, nil
}

func loadBrokerPackages(root string) ([]*surfacePackage, *token.FileSet, error) {
	set := token.NewFileSet()
	byKey := make(map[string]*surfacePackage)
	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("broker tree must not contain a symlink: %s", filePath)
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		syntax, err := parser.ParseFile(set, filePath, nil, parser.AllErrors)
		if err != nil {
			return fmt.Errorf("parse %s: %w", filePath, err)
		}
		directory := filepath.Dir(filePath)
		key := directory + "\x00" + syntax.Name.Name
		pkg := byKey[key]
		if pkg == nil {
			pkg = &surfacePackage{directory: directory, name: syntax.Name.Name}
			byKey[key] = pkg
		}
		file, err := newSurfaceFile(filePath, syntax)
		if err != nil {
			return err
		}
		pkg.files = append(pkg.files, file)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	packages := make([]*surfacePackage, 0, len(byKey))
	for _, pkg := range byKey {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].directory == packages[j].directory {
			return packages[i].name < packages[j].name
		}
		return packages[i].directory < packages[j].directory
	})
	return packages, set, nil
}

func newSurfaceFile(filePath string, syntax *ast.File) (*surfaceFile, error) {
	file := &surfaceFile{path: filePath, syntax: syntax}
	for _, declaration := range syntax.Imports {
		importPath, err := strconv.Unquote(declaration.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("decode import in %s: %w", filePath, err)
		}
		if declaration.Name != nil && declaration.Name.Name == "." && isSensitiveImport(importPath) {
			file.dotSensitivePath = importPath
		}
	}
	return file, nil
}

func isSensitiveImport(importPath string) bool {
	for _, root := range sensitiveImportRoots {
		if importPath == root || strings.HasPrefix(importPath, root+"/") {
			return true
		}
	}
	return false
}

func syntaxFiles(files []*surfaceFile) []*ast.File {
	result := make([]*ast.File, 0, len(files))
	for _, file := range files {
		result = append(result, file.syntax)
	}
	return result
}

func surfaceImportPath(root, directory string) string {
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." {
		return moduleImportPath + "/internal/broker/__surface"
	}
	return moduleImportPath + "/internal/broker/__surface/" + filepath.ToSlash(relative)
}

func (source *moduleSourceImporter) Import(importPath string) (*types.Package, error) {
	if cached := source.cache[importPath]; cached != nil {
		return cached, nil
	}
	if !strings.HasPrefix(importPath, moduleImportPath+"/") {
		return source.fallback.Import(importPath)
	}
	if source.loading[importPath] {
		return nil, fmt.Errorf("module source import cycle at %s", importPath)
	}
	source.loading[importPath] = true
	defer delete(source.loading, importPath)
	directory := filepath.Join(source.moduleRoot, filepath.FromSlash(strings.TrimPrefix(importPath, moduleImportPath+"/")))
	files, name, err := parsePackageDirectory(source.set, source.moduleRoot, directory)
	if err != nil {
		return nil, fmt.Errorf("import %s: %w", importPath, err)
	}
	config := types.Config{Importer: source, IgnoreFuncBodies: true}
	checked, err := config.Check(importPath, source.set, files, nil)
	if err != nil {
		return nil, fmt.Errorf("type-check imported package %s (%s): %w", importPath, name, err)
	}
	source.cache[importPath] = checked
	return checked, nil
}

func parsePackageDirectory(set *token.FileSet, moduleRoot, directory string) ([]*ast.File, string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(moduleRoot)
	if err != nil {
		return nil, "", err
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, "", err
	}
	if !pathWithin(resolvedRoot, resolvedDirectory) {
		return nil, "", fmt.Errorf("package directory escapes module root")
	}
	entries, err := os.ReadDir(resolvedDirectory)
	if err != nil {
		return nil, "", err
	}
	var files []*ast.File
	packageName := ""
	for _, entry := range entries {
		if entry.Type()&fs.ModeSymlink != 0 && filepath.Ext(entry.Name()) == ".go" {
			return nil, "", fmt.Errorf("module Go source must not be a symlink: %s", entry.Name())
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		filePath := filepath.Join(resolvedDirectory, entry.Name())
		syntax, err := parser.ParseFile(set, filePath, nil, parser.AllErrors)
		if err != nil {
			return nil, "", err
		}
		if packageName == "" {
			packageName = syntax.Name.Name
		} else if packageName != syntax.Name.Name {
			return nil, "", fmt.Errorf("multiple production packages in %s", resolvedDirectory)
		}
		files = append(files, syntax)
	}
	if len(files) == 0 {
		return nil, "", fmt.Errorf("no production Go files in %s", resolvedDirectory)
	}
	return files, packageName, nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:0]
	for index, value := range values {
		if index == 0 || value != values[index-1] {
			result = append(result, value)
		}
	}
	return result
}

func (pkg *surfacePackage) publicSurfaceViolations(checked *types.Package, info *types.Info) []string {
	var violations []string
	for _, file := range pkg.files {
		if file.dotSensitivePath != "" {
			violations = append(violations, pkg.violation(file.path, "dot import", file.dotSensitivePath))
		}
	}
	scope := checked.Scope()
	for _, name := range scope.Names() {
		if !token.IsExported(name) {
			continue
		}
		object := scope.Lookup(name)
		if forbiddenCapabilityNames[name] || exposesSecurityType(object.Type(), make(map[types.Type]bool)) {
			violations = append(violations, pkg.violation(pkg.directory, objectKind(object), name))
		}
	}
	for _, file := range pkg.files {
		for _, declaration := range file.syntax.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || !function.Name.IsExported() {
				continue
			}
			object := info.Defs[function.Name]
			if object != nil && (forbiddenCapabilityNames[object.Name()] || exposesSecurityType(object.Type(), make(map[types.Type]bool))) {
				violations = append(violations, pkg.violation(file.path, "method", object.Name()))
			}
		}
	}
	return violations
}

func (pkg *surfacePackage) violation(filePath, kind, name string) string {
	return fmt.Sprintf("%s: package %s %s %s exposes connector or policy capability", filePath, pkg.name, kind, name)
}

func objectKind(object types.Object) string {
	switch object.(type) {
	case *types.TypeName:
		return "type"
	case *types.Func:
		return "function"
	case *types.Var:
		return "value"
	case *types.Const:
		return "constant"
	default:
		return "object"
	}
}
