package quality

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyFuzzManifestRequiresExactSeededTargets(t *testing.T) {
	root := t.TempDir()
	writeFuzzSource(t, root, "pkg/fuzz_test.go", `package pkg
import "testing"
func FuzzAlpha(f *testing.F) { f.Add([]byte("seed")); f.Fuzz(func(*testing.T, []byte) {}) }
`)
	manifest := writeFuzzManifest(t, root, "./pkg FuzzAlpha\n")
	targets, err := VerifyFuzzManifest(context.Background(), root, manifest)
	if err != nil || len(targets) != 1 || targets[0].Name != "FuzzAlpha" {
		t.Fatalf("targets=%+v err=%v", targets, err)
	}
}

func TestVerifyFuzzManifestRejectsManifestAndSourceBypasses(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		source   string
		code     ErrorCode
	}{
		{name: "empty", manifest: "# none\n", source: seededFuzzSource("FuzzAlpha"), code: CodeDenied},
		{name: "traversal", manifest: "./../pkg FuzzAlpha\n", source: seededFuzzSource("FuzzAlpha"), code: CodeInvalidInput},
		{name: "duplicate", manifest: "./pkg FuzzAlpha\n./pkg FuzzAlpha\n", source: seededFuzzSource("FuzzAlpha"), code: CodeInvalidInput},
		{name: "unlisted", manifest: "./pkg FuzzAlpha\n", source: `package pkg
import "testing"
func FuzzAlpha(f *testing.F) { f.Add("a"); f.Fuzz(func(*testing.T, string) {}) }
func FuzzBeta(f *testing.F) { f.Add("b"); f.Fuzz(func(*testing.T, string) {}) }
`, code: CodeDenied},
		{name: "comment is not seed", manifest: "./pkg FuzzAlpha\n", source: `package pkg
import "testing"
func FuzzAlpha(f *testing.F) { /* f.Add("fake") */ f.Fuzz(func(*testing.T, string) {}) }
`, code: CodeDenied},
		{name: "nested seed is not registration", manifest: "./pkg FuzzAlpha\n", source: `package pkg
import "testing"
func FuzzAlpha(f *testing.F) { _ = func() { f.Add("hidden") }; f.Fuzz(func(*testing.T, string) {}) }
`, code: CodeDenied},
		{name: "dead branch is rejected", manifest: "./pkg FuzzAlpha\n", source: `package pkg
import "testing"
func FuzzAlpha(f *testing.F) { f.Add("live"); if false { f.Add("dead") }; f.Fuzz(func(*testing.T, string) {}) }
`, code: CodeDenied},
		{name: "shadowed parameter is rejected", manifest: "./pkg FuzzAlpha\n", source: `package pkg
import "testing"
func FuzzAlpha(f *testing.F) { f.Add("live"); _ = func(f *testing.F) { f.Add("shadow") }; f.Fuzz(func(*testing.T, string) {}) }
`, code: CodeDenied},
		{name: "seed after callback is rejected", manifest: "./pkg FuzzAlpha\n", source: `package pkg
import "testing"
func FuzzAlpha(f *testing.F) { f.Fuzz(func(*testing.T, string) {}); f.Add("late") }
`, code: CodeDenied},
		{name: "parameter reassignment is rejected", manifest: "./pkg FuzzAlpha\n", source: `package pkg
import "testing"
func FuzzAlpha(f *testing.F) { f.Add("seed"); f = nil; f.Fuzz(func(*testing.T, string) {}) }
`, code: CodeDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeFuzzSource(t, root, "pkg/fuzz_test.go", test.source)
			manifest := writeFuzzManifest(t, root, test.manifest)
			if _, err := VerifyFuzzManifest(context.Background(), root, manifest); CodeOf(err) != test.code {
				t.Fatalf("code=%q err=%v, want %q", CodeOf(err), err, test.code)
			}
		})
	}
}

func TestVerifyFuzzExecutionRequiresRunAndPassSeedCallback(t *testing.T) {
	root := t.TempDir()
	valid := writeFuzzTrace(t, root, `
{"Action":"run","Test":"FuzzAlpha"}
{"Action":"run","Test":"FuzzAlpha/seed#0"}
{"Action":"pass","Test":"FuzzAlpha/seed#0"}
{"Action":"pass","Test":"FuzzAlpha"}
`)
	if count, err := VerifyFuzzExecution(context.Background(), valid, "FuzzAlpha"); err != nil || count != 1 {
		t.Fatal(err)
	}
	invalid := []string{
		`{"Action":"run","Test":"FuzzAlpha"}
{"Action":"pass","Test":"FuzzAlpha"}
`,
		`{"Action":"output","Test":"FuzzAlpha/seed#0"}
{"Action":"output","Test":"FuzzAlpha","Output":"fake pass"}
`,
		`{"Action":"run","Test":"FuzzAlpha"}
{"Action":"pass","Test":"FuzzAlpha/seed#0"}
{"Action":"pass","Test":"FuzzAlpha"}
`,
	}
	for index, content := range invalid {
		path := writeFuzzTrace(t, root, content)
		if _, err := VerifyFuzzExecution(context.Background(), path, "FuzzAlpha"); CodeOf(err) != CodeDenied {
			t.Fatalf("invalid trace %d code=%q err=%v", index, CodeOf(err), err)
		}
	}
}

func TestVerifyFuzzExecutionHonorsCancellation(t *testing.T) {
	path := writeFuzzTrace(t, t.TempDir(), `{"Action":"run","Test":"FuzzAlpha"}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyFuzzExecution(ctx, path, "FuzzAlpha"); CodeOf(err) != CodeCanceled {
		t.Fatalf("code=%q err=%v, want canceled", CodeOf(err), err)
	}
}

func TestVerifyFuzzManifestHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	writeFuzzSource(t, root, "pkg/fuzz_test.go", seededFuzzSource("FuzzAlpha"))
	manifest := writeFuzzManifest(t, root, "./pkg FuzzAlpha\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyFuzzManifest(ctx, root, manifest); CodeOf(err) != CodeCanceled {
		t.Fatalf("code=%q err=%v, want canceled", CodeOf(err), err)
	}
}

func seededFuzzSource(name string) string {
	return "package pkg\nimport \"testing\"\nfunc " + name + "(f *testing.F) { f.Add(\"seed\"); f.Fuzz(func(*testing.T, string) {}) }\n"
}

func writeFuzzManifest(t *testing.T, root, content string) string {
	t.Helper()
	path := filepath.Join(root, "fuzz-targets.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFuzzSource(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFuzzTrace(t *testing.T, root, content string) string {
	t.Helper()
	path := filepath.Join(root, "fuzz-execution.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
