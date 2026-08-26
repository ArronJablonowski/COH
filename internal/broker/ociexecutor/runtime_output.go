package ociexecutor

import (
	"bytes"
	"sync"
)

type boundedOutput struct {
	mu        sync.Mutex
	limit     uint64
	written   uint64
	truncated bool
	exceeded  chan struct{}
	once      sync.Once
	stdout    *boundedStream
	stderr    *boundedStream
}

type boundedStream struct {
	owner  *boundedOutput
	buffer bytes.Buffer
}

func newBoundedOutput(limit uint64) *boundedOutput {
	value := &boundedOutput{limit: limit, exceeded: make(chan struct{})}
	value.stdout = &boundedStream{owner: value}
	value.stderr = &boundedStream{owner: value}
	return value
}

func (stream *boundedStream) Write(data []byte) (int, error) {
	stream.owner.mu.Lock()
	defer stream.owner.mu.Unlock()
	remaining := uint64(0)
	if stream.owner.written < stream.owner.limit {
		remaining = stream.owner.limit - stream.owner.written
	}
	keep := len(data)
	if uint64(keep) > remaining {
		keep = int(remaining)
		stream.owner.truncated = true
		stream.owner.once.Do(func() { close(stream.owner.exceeded) })
	}
	if keep > 0 {
		_, _ = stream.buffer.Write(data[:keep])
		stream.owner.written += uint64(keep)
	}
	return len(data), nil
}

func (output *boundedOutput) snapshot() ([]byte, []byte, bool) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return bytes.Clone(output.stdout.buffer.Bytes()), bytes.Clone(output.stderr.buffer.Bytes()), output.truncated
}
