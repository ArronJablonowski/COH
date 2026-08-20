package supplychain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLifecycleRejectsCanceledAndExpiredContextBeforeMutation(t *testing.T) {
	prefix := t.TempDir()
	if err := os.Chmod(prefix, 0o700); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunLifecycle(canceled, "remove", "", prefix, ""); CodeOf(err) != CodeCanceled {
		t.Fatalf("canceled code=%q err=%v", CodeOf(err), err)
	}
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	if err := RunLifecycle(expired, "remove", "", prefix, ""); CodeOf(err) != CodeTimeout {
		t.Fatalf("timeout code=%q err=%v", CodeOf(err), err)
	}
	entries, err := os.ReadDir(prefix)
	if err != nil || len(entries) != 0 {
		t.Fatalf("canceled lifecycle mutated prefix: entries=%v err=%v", entries, err)
	}
}

func TestLifecyclePreservesCancellationDuringActualCopyAndRecovers(t *testing.T) {
	source := makeLifecycleSource(t)
	prefix := t.TempDir()
	if err := os.Chmod(prefix, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := &pathCancellationContext{path: filepath.Join(prefix, "releases", "v0.1.0", "bin", "archcheck"), requireBytes: true}
	if err := RunLifecycle(ctx, "install", source, prefix, "v0.1.0"); CodeOf(err) != CodeCanceled {
		t.Fatalf("copy cancellation code=%q err=%v", CodeOf(err), err)
	}
	if _, err := os.Lstat(filepath.Join(prefix, ".coh-lifecycle-pending")); err != nil {
		t.Fatalf("canceled operation lost recovery journal: %v", err)
	}
	if err := RunLifecycle(context.Background(), "install", source, prefix, "v0.1.0"); err != nil {
		t.Fatalf("recovery retry failed: %v", err)
	}
}

type pathCancellationContext struct {
	path         string
	requireBytes bool
}

func (ctx *pathCancellationContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *pathCancellationContext) Done() <-chan struct{}       { return nil }
func (ctx *pathCancellationContext) Value(any) any               { return nil }
func (ctx *pathCancellationContext) Err() error {
	info, err := os.Stat(ctx.path)
	if err == nil && (!ctx.requireBytes || info.Size() > 0) {
		return context.Canceled
	}
	return nil
}

func makeLifecycleSource(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "share", "coh"), 0o700); err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{
		"bin/archcheck":                bytes.Repeat([]byte("a"), 1<<20),
		"bin/installgate":              []byte("installgate\n"),
		"bin/qualitygate":              []byte("qualitygate\n"),
		"share/coh/LICENSE":            []byte("license\n"),
		"share/coh/install_release.sh": []byte("#!/bin/bash\n"),
	}
	var manifest strings.Builder
	for _, name := range installedFiles {
		data := contents[name]
		mode := os.FileMode(0o444)
		if strings.HasPrefix(name, "bin/") || name == "share/coh/install_release.sh" {
			mode = 0o555
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), data, mode); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(digest[:]), name)
	}
	if err := os.WriteFile(filepath.Join(root, "share", "coh", "release-files.sha256"), []byte(manifest.String()), 0o444); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLifecycleReaderStopsAfterMidStreamCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterRead{reader: bytes.NewReader(bytes.Repeat([]byte("x"), 1024)), cancel: cancel}
	_, err := io.Copy(io.Discard, &contextReader{ctx: ctx, reader: reader})
	if CodeOf(err) != CodeCanceled {
		t.Fatalf("mid-stream cancellation code=%q err=%v", CodeOf(err), err)
	}
}

type cancelAfterRead struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (reader *cancelAfterRead) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer[:min(len(buffer), 16)])
	reader.cancel()
	return count, err
}
