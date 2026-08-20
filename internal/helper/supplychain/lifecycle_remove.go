package supplychain

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"slices"
)

func removeAllReleaseTrees(ctx context.Context, root *os.Root) error {
	entries, err := fs.ReadDir(root.FS(), "releases")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return lifecycleFailure("remove", err)
	}
	if len(entries) > 64 {
		return errorf(CodeDenied, "remove", "release inventory exceeds bound", nil)
	}
	for _, entry := range entries {
		if err := lifecycleContext(ctx, "remove"); err != nil {
			return err
		}
		info, infoErr := root.Lstat("releases/" + entry.Name())
		if infoErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !validVersion(entry.Name()) {
			return errorf(CodeDenied, "remove", "release inventory contains an unsafe entry", infoErr)
		}
		if err := removeContainedRelease(ctx, root, entry.Name()); err != nil {
			return err
		}
	}
	if err := root.Remove("releases"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return lifecycleFailure("remove", err)
	}
	return syncRoot(root)
}

func removeContainedRelease(ctx context.Context, root *os.Root, version string) error {
	if !validVersion(version) {
		return errorf(CodeDenied, "remove", "release version is unsafe", nil)
	}
	base := "releases/" + version
	for _, name := range append(slices.Clone(installedFiles), "share/coh/release-files.sha256") {
		if err := lifecycleContext(ctx, "remove"); err != nil {
			return err
		}
		if err := removeRootEntry(root, base+"/"+name); err != nil {
			return err
		}
	}
	for _, name := range []string{base + "/bin", base + "/share/coh", base + "/share", base} {
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errorf(CodeDenied, "remove", "release tree contains unexpected entries", err)
		}
	}
	return nil
}
