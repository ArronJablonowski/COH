//go:build darwin || linux

package nativeexecutor

import (
	"bytes"
	"io"
	"os"
	"sync"
	"syscall"
)

type boundedOutput struct {
	mu        sync.Mutex
	remaining uint64
	stdout    bytes.Buffer
	stderr    bytes.Buffer
	overflow  bool
}

type boundedWriter struct {
	output *boundedOutput
	stderr bool
}

func newBoundedOutput(limit uint64) *boundedOutput { return &boundedOutput{remaining: limit} }

func (output *boundedOutput) writer(stderr bool) io.Writer {
	return boundedWriter{output: output, stderr: stderr}
}

func (writer boundedWriter) Write(data []byte) (int, error) {
	writer.output.mu.Lock()
	defer writer.output.mu.Unlock()
	allowed := min(uint64(len(data)), writer.output.remaining)
	target := &writer.output.stdout
	if writer.stderr {
		target = &writer.output.stderr
	}
	_, _ = target.Write(data[:allowed])
	writer.output.remaining -= allowed
	if allowed != uint64(len(data)) {
		writer.output.overflow = true
		return int(allowed), io.ErrShortWrite
	}
	return len(data), nil
}

func (output *boundedOutput) exceeded() bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.overflow
}

func (output *boundedOutput) result(state *os.ProcessState) SandboxResult {
	output.mu.Lock()
	defer output.mu.Unlock()
	exitCode := -1
	signal := ""
	if state != nil {
		exitCode = state.ExitCode()
		if wait, ok := state.Sys().(syscall.WaitStatus); ok && wait.Signaled() {
			signal = wait.Signal().String()
		}
	}
	return SandboxResult{ExitCode: exitCode, TerminationSignal: signal, StandardOutput: bytes.Clone(output.stdout.Bytes()),
		StandardError: bytes.Clone(output.stderr.Bytes()), OutputTruncated: output.overflow}
}
