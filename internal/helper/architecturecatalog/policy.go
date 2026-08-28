package architecturecatalog

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var forbiddenLoaderImports = map[string]bool{
	"plugin": true, "github.com/hashicorp/go-plugin": true,
	"github.com/traefik/yaegi": true, "github.com/traefik/yaegi/interp": true,
}

func validateSourcePolicy(root string) error {
	for _, tree := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				return fmt.Errorf("symlink denied in Go source tree")
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relativePath := filepath.ToSlash(relative)
			if parsed.Name.Name == "main" && !strings.HasPrefix(relativePath, "cmd/") &&
				!strings.Contains(relativePath, "/testdata/") {
				return fmt.Errorf("alternate launch path %s", filepath.ToSlash(relative))
			}
			for _, imported := range parsed.Imports {
				name, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return err
				}
				if name == "C" || forbiddenLoaderImports[name] {
					return fmt.Errorf("forbidden dynamic loader %s in %s", name, filepath.ToSlash(relative))
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func allGoSourcePaths(root string) ([]string, error) {
	var paths []string
	for _, tree := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && filepath.Ext(path) == ".go" {
				relative, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				paths = append(paths, filepath.ToSlash(relative))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(paths)
	return paths, nil
}
