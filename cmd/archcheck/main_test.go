package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/helper/architecture"
)

func TestRunCanonicalAndInvalidArguments(t *testing.T) {
	contract := filepath.Join("..", "..", "contracts", "architecture", "v1", "workspace-contract.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-mode", "canonical", "-contract", contract}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(canonical) code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), `{"schema_version":"coh.architecture/v1"`) {
		t.Fatalf("canonical output prefix = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-format", "yaml"}, &stdout, &stderr)
	if code != 64 || !strings.Contains(stderr.String(), "invalid arguments") {
		t.Fatalf("run(invalid) code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunFailsWhenCanonicalOutputCannotBeWritten(t *testing.T) {
	contract := filepath.Join("..", "..", "contracts", "architecture", "v1", "workspace-contract.json")
	var stderr bytes.Buffer
	code := run([]string{"-mode", "canonical", "-contract", contract}, failingWriter{}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "cannot write canonical contract") {
		t.Fatalf("run() code = %d, stderr = %q", code, stderr.String())
	}
}

func TestWriteReportPropagatesViolationWriteFailure(t *testing.T) {
	report := architecture.Report{
		Outcome:    "denied",
		Violations: []architecture.Violation{{Rule: "ARCH-002", Package: "source", Import: "target"}},
	}
	writer := &failAfterWriter{remainingWrites: 1}
	if err := writeReport(writer, "text", report); err == nil {
		t.Fatal("writeReport() error = nil, want output failure")
	}
}

func TestWriteReportPropagatesJSONWriteFailure(t *testing.T) {
	if err := writeReport(failingWriter{}, "json", architecture.Report{Outcome: "allowed"}); err == nil {
		t.Fatal("writeReport(json) error = nil, want output failure")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("sink unavailable") }

type failAfterWriter struct {
	remainingWrites int
}

func (w *failAfterWriter) Write(data []byte) (int, error) {
	if w.remainingWrites == 0 {
		return 0, io.ErrClosedPipe
	}
	w.remainingWrites--
	return len(data), nil
}
