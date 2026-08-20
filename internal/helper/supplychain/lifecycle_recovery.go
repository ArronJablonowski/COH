package supplychain

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

func writeLifecyclePending(root *os.Root, pending lifecyclePending) error {
	if !slices.Contains([]string{"install", "upgrade", "rollback", "remove"}, pending.Operation) || !validVersion(pending.Version) {
		return errorf(CodeInvalidInput, "recovery", "pending lifecycle record is invalid", nil)
	}
	data := []byte(fmt.Sprintf("schema=coh.lifecycle-pending/v1\noperation=%s\nversion=%s\n", pending.Operation, pending.Version))
	file, err := root.OpenFile(".coh-lifecycle-pending", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return lifecycleFailure("recovery", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return lifecycleFailure("recovery", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return lifecycleFailure("recovery", err)
	}
	if err := file.Close(); err != nil {
		return lifecycleFailure("recovery", err)
	}
	return syncRoot(root)
}

func recoverLifecycle(ctx context.Context, root *os.Root) (lifecyclePending, error) {
	if err := lifecycleContext(ctx, "recovery"); err != nil {
		return lifecyclePending{}, err
	}
	data, err := root.ReadFile(".coh-lifecycle-pending")
	if errors.Is(err, os.ErrNotExist) {
		return lifecyclePending{}, nil
	}
	if err != nil || len(data) > 512 {
		return lifecyclePending{}, lifecycleFailure("recovery", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 3 || lines[0] != "schema=coh.lifecycle-pending/v1" {
		return lifecyclePending{}, errorf(CodeDenied, "recovery", "pending lifecycle record is malformed", nil)
	}
	pending := lifecyclePending{Operation: strings.TrimPrefix(lines[1], "operation="), Version: strings.TrimPrefix(lines[2], "version=")}
	if lines[1] != "operation="+pending.Operation || lines[2] != "version="+pending.Version ||
		!slices.Contains([]string{"install", "upgrade", "rollback", "remove"}, pending.Operation) || !validVersion(pending.Version) {
		return lifecyclePending{}, errorf(CodeDenied, "recovery", "pending lifecycle fields are invalid", nil)
	}
	if pending.Operation == "remove" {
		entries, readErr := fs.ReadDir(root.FS(), ".")
		if readErr != nil {
			return lifecyclePending{}, lifecycleFailure("recovery", readErr)
		}
		for _, entry := range entries {
			if !slices.Contains([]string{".coh-install-root", ".coh-lifecycle-pending", "releases", "state"}, entry.Name()) {
				return lifecyclePending{}, errorf(CodeDenied, "recovery", "remove recovery found an unexpected entry", nil)
			}
		}
		if err := lifecycleFault("recovery_cleanup"); err != nil {
			return lifecyclePending{}, err
		}
		if err := removeAllReleaseTrees(ctx, root); err != nil {
			return lifecyclePending{}, err
		}
		if err := removeRootEntry(root, "state"); err != nil {
			return lifecyclePending{}, err
		}
		if err := removeRootEntry(root, ".coh-install-root"); err != nil {
			return lifecyclePending{}, err
		}
		if err := syncRoot(root); err != nil {
			return lifecyclePending{}, err
		}
		remaining, readErr := fs.ReadDir(root.FS(), ".")
		if readErr != nil || !equalNames(remaining, []string{".coh-lifecycle-pending"}) {
			return lifecyclePending{}, errorf(CodeDenied, "recovery", "remove recovery postcondition differs", readErr)
		}
		if err := removePending(root); err != nil {
			return lifecyclePending{}, err
		}
		return pending, nil
	}
	state, stateErr := readInstallState(root)
	if stateErr == nil && state.Current == pending.Version {
		current, openErr := root.OpenRoot("releases/" + state.Current)
		if openErr != nil {
			return lifecyclePending{}, lifecycleFailure("recovery", openErr)
		}
		_, verifyErr := verifyReleaseTree(ctx, current, state.CurrentManifest)
		current.Close()
		if verifyErr != nil {
			return lifecyclePending{}, verifyErr
		}
		if err := removePending(root); err != nil {
			return lifecyclePending{}, err
		}
		return pending, nil
	}
	if pending.Operation == "install" {
		if err := lifecycleFault("recovery_cleanup"); err != nil {
			return lifecyclePending{}, err
		}
		if err := removeAllReleaseTrees(ctx, root); err != nil {
			return lifecyclePending{}, err
		}
		if err := removeRootEntry(root, "state"); err != nil {
			return lifecyclePending{}, err
		}
		if err := removeRootEntry(root, ".coh-install-root"); err != nil {
			return lifecyclePending{}, err
		}
		if err := syncRoot(root); err != nil {
			return lifecyclePending{}, err
		}
		remaining, readErr := fs.ReadDir(root.FS(), ".")
		if readErr != nil || !equalNames(remaining, []string{".coh-lifecycle-pending"}) {
			return lifecyclePending{}, errorf(CodeDenied, "recovery", "install recovery postcondition differs", readErr)
		}
	} else if pending.Operation == "rollback" {
		if stateErr != nil {
			return lifecyclePending{}, errorf(CodeDenied, "recovery", "existing install state is invalid", stateErr)
		}
	} else {
		if stateErr != nil {
			return lifecyclePending{}, errorf(CodeDenied, "recovery", "existing install state is invalid", stateErr)
		}
		if err := lifecycleFault("recovery_cleanup"); err != nil {
			return lifecyclePending{}, err
		}
		if err := removeContainedRelease(ctx, root, pending.Version); err != nil {
			return lifecyclePending{}, err
		}
		if err := syncRootPath(root, "releases"); err != nil {
			return lifecyclePending{}, err
		}
		if _, err := root.Lstat("releases/" + pending.Version); !errors.Is(err, os.ErrNotExist) {
			return lifecyclePending{}, errorf(CodeDenied, "recovery", "orphan release survived cleanup", err)
		}
		if err := syncRoot(root); err != nil {
			return lifecyclePending{}, err
		}
	}
	if err := removePending(root); err != nil {
		return lifecyclePending{}, err
	}
	return lifecyclePending{}, nil
}

func removeRootEntry(root *os.Root, name string) error {
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return lifecycleFailure("recovery", err)
	}
	return nil
}

func lifecycleFault(point string) error {
	if os.Getenv("COH_LIFECYCLE_TEST_FAULT") == point {
		return errorf(CodeToolFailure, "fault", "injected lifecycle interruption", nil)
	}
	return nil
}
