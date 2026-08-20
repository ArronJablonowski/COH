package supplychain

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

func readInstallState(root *os.Root) (installState, error) {
	marker, err := root.ReadFile(".coh-install-root")
	if err != nil || string(marker) != "coh.install-root/v1\n" {
		return installState{}, errorf(CodeDenied, "marker", "install marker is missing or invalid", err)
	}
	data, err := root.ReadFile("state")
	if err != nil || len(data) > 4096 {
		return installState{}, lifecycleFailure("state", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 5 || lines[0] != "schema=coh.install-state/v1" {
		return installState{}, errorf(CodeDenied, "state", "install state is malformed", nil)
	}
	state := installState{
		Current: strings.TrimPrefix(lines[1], "current="), Previous: strings.TrimPrefix(lines[2], "previous="),
		CurrentManifest: strings.TrimPrefix(lines[3], "current_manifest="), PreviousManifest: strings.TrimPrefix(lines[4], "previous_manifest="),
	}
	if lines[1] != "current="+state.Current || lines[2] != "previous="+state.Previous ||
		lines[3] != "current_manifest="+state.CurrentManifest || lines[4] != "previous_manifest="+state.PreviousManifest ||
		!validVersion(state.Current) || state.Previous != "-" && !validVersion(state.Previous) ||
		!validDigest(state.CurrentManifest) || state.PreviousManifest != "-" && !validDigest(state.PreviousManifest) {
		return installState{}, errorf(CodeDenied, "state", "install state fields are invalid", nil)
	}
	return state, nil
}

func writeInstallState(root *os.Root, state installState, initial bool) error {
	data := []byte(fmt.Sprintf("schema=coh.install-state/v1\ncurrent=%s\nprevious=%s\ncurrent_manifest=%s\nprevious_manifest=%s\n", state.Current, state.Previous, state.CurrentManifest, state.PreviousManifest))
	temporary := ".state.pending"
	_ = root.Remove(temporary)
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return lifecycleFailure("state", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return lifecycleFailure("state", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return lifecycleFailure("state", err)
	}
	if err := file.Close(); err != nil {
		return lifecycleFailure("state", err)
	}
	if initial {
		if err := root.Link(temporary, "state"); err != nil {
			return errorf(CodeDenied, "state", "install state already exists", err)
		}
		if err := root.Remove(temporary); err != nil {
			return lifecycleFailure("state", err)
		}
		return syncRoot(root)
	}
	if err := root.Rename(temporary, "state"); err != nil {
		return lifecycleFailure("state", err)
	}
	return syncRoot(root)
}

func lifecycleFailure(field string, err error) error {
	if err == nil {
		return errorf(CodeDenied, field, "lifecycle contract denied", nil)
	}
	return errorf(CodeDenied, field, "lifecycle filesystem operation denied", err)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := lifecycleContext(reader.ctx, "io"); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func lifecycleContext(ctx context.Context, field string) error {
	if err := ctx.Err(); err != nil {
		return contextError(err, field)
	}
	return nil
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return lifecycleFailure("durability", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return lifecycleFailure("durability", err)
	}
	return nil
}

func syncRootPath(root *os.Root, name string) error {
	nested, err := root.OpenRoot(name)
	if err != nil {
		return lifecycleFailure("durability", err)
	}
	defer nested.Close()
	return syncRoot(nested)
}

func syncReleaseTree(root *os.Root) error {
	for _, directory := range []string{"bin", "share/coh", "share", "."} {
		if err := syncRootPath(root, directory); err != nil {
			return err
		}
	}
	return nil
}

func removePending(root *os.Root) error {
	if err := root.Remove(".coh-lifecycle-pending"); err != nil {
		return lifecycleFailure("recovery", err)
	}
	return syncRoot(root)
}
