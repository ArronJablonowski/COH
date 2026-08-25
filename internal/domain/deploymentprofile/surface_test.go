package deploymentprofile

import (
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

func TestValidatorHasNoHostDockerOrNetworkProbeSurface(t *testing.T) {
	files, err := parser.ParseDir(token.NewFileSet(), ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	denied := map[string]bool{
		"net": true, "net/http": true, "os": true, "os/exec": true,
		"path/filepath": true, "runtime": true, "syscall": true,
	}
	for _, pkg := range files {
		for _, file := range pkg.Files {
			for _, imported := range file.Imports {
				path, unquoteErr := strconv.Unquote(imported.Path.Value)
				if unquoteErr != nil {
					t.Fatal(unquoteErr)
				}
				if denied[path] {
					t.Errorf("production validator imports host-probe package %q", path)
				}
			}
		}
	}
}
