package supplychain

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var installedFiles = []string{
	"bin/archcheck",
	"bin/installgate",
	"bin/qualitygate",
	"share/coh/LICENSE",
	"share/coh/install_release.sh",
}

type installState struct {
	Current, Previous                 string
	CurrentManifest, PreviousManifest string
}

type lifecyclePending struct {
	Operation string
	Version   string
}

func RunLifecycle(ctx context.Context, operation, sourcePath, prefixPath, version string) error {
	if err := lifecycleContext(ctx, "lifecycle"); err != nil {
		return err
	}
	if !slices.Contains([]string{"install", "verify", "upgrade", "rollback", "remove"}, operation) {
		return errorf(CodeInvalidInput, "operation", "unsupported lifecycle operation", nil)
	}
	prefix, err := openPrivateRoot(prefixPath)
	if err != nil {
		return err
	}
	defer prefix.Close()
	recovered, err := recoverLifecycle(ctx, prefix)
	if err != nil {
		return err
	}
	var source *os.Root
	var sourceManifest string
	if sourcePath != "" {
		source, err = openRealRoot(sourcePath, "source")
		if err != nil {
			return err
		}
		defer source.Close()
		sourceManifest, err = verifyReleaseTree(ctx, source, "")
		if err != nil {
			return err
		}
	}
	if recovered.Operation == operation && (operation == "remove" || operation == "rollback" || recovered.Version == version) {
		if operation == "install" || operation == "upgrade" {
			state, stateErr := readInstallState(prefix)
			if stateErr != nil || source == nil || state.Current != recovered.Version || state.CurrentManifest != sourceManifest {
				return errorf(CodeDenied, "recovery", "recovered state differs from verified source", stateErr)
			}
		}
		return nil
	}
	switch operation {
	case "install":
		if source == nil || !validVersion(version) {
			return errorf(CodeInvalidInput, "install", "source and semantic version are required", nil)
		}
		if names, readErr := fs.ReadDir(prefix.FS(), "."); readErr != nil || len(names) != 0 {
			return errorf(CodeDenied, "prefix", "install prefix must be empty", readErr)
		}
		if err := writeLifecyclePending(prefix, lifecyclePending{Operation: operation, Version: version}); err != nil {
			return err
		}
		if err := lifecycleContext(ctx, "install"); err != nil {
			return err
		}
		if err := prefix.WriteFile(".coh-install-root", []byte("coh.install-root/v1\n"), 0o600); err != nil {
			return lifecycleFailure("marker", err)
		}
		if err := prefix.Mkdir("releases", 0o700); err != nil {
			return lifecycleFailure("releases", err)
		}
		if err := syncRoot(prefix); err != nil {
			return err
		}
		if err := lifecycleFault("install_after_marker"); err != nil {
			return err
		}
		if err := installRelease(ctx, prefix, source, version, sourceManifest); err != nil {
			return err
		}
		if err := writeInstallState(prefix, installState{Current: version, Previous: "-", CurrentManifest: sourceManifest, PreviousManifest: "-"}, true); err != nil {
			return err
		}
		if err := lifecycleFault("install_after_state"); err != nil {
			return err
		}
		return removePending(prefix)
	case "verify":
		if version != "" {
			return errorf(CodeInvalidInput, "verify", "verify does not accept a version", nil)
		}
		state, stateErr := readInstallState(prefix)
		if stateErr != nil {
			return stateErr
		}
		installed, openErr := prefix.OpenRoot("releases/" + state.Current)
		if openErr != nil {
			return lifecycleFailure("release", openErr)
		}
		defer installed.Close()
		if _, err := verifyReleaseTree(ctx, installed, state.CurrentManifest); err != nil {
			return err
		}
		if source != nil && sourceManifest != state.CurrentManifest {
			return errorf(CodeDenied, "release", "installed release differs from verified source", nil)
		}
		return nil
	case "upgrade":
		if source == nil || !validVersion(version) {
			return errorf(CodeInvalidInput, "upgrade", "source and semantic version are required", nil)
		}
		state, stateErr := readInstallState(prefix)
		if stateErr != nil {
			return stateErr
		}
		if version == state.Current {
			return errorf(CodeDenied, "upgrade", "version is already current", nil)
		}
		if err := writeLifecyclePending(prefix, lifecyclePending{Operation: operation, Version: version}); err != nil {
			return err
		}
		if err := lifecycleContext(ctx, "upgrade"); err != nil {
			return err
		}
		if err := installRelease(ctx, prefix, source, version, sourceManifest); err != nil {
			return err
		}
		if err := lifecycleFault("upgrade_after_release"); err != nil {
			return err
		}
		if err := writeInstallState(prefix, installState{Current: version, Previous: state.Current, CurrentManifest: sourceManifest, PreviousManifest: state.CurrentManifest}, false); err != nil {
			return err
		}
		if err := lifecycleFault("upgrade_after_state"); err != nil {
			return err
		}
		return removePending(prefix)
	case "rollback":
		if source != nil || version != "" {
			return errorf(CodeInvalidInput, "rollback", "rollback accepts only a prefix", nil)
		}
		state, stateErr := readInstallState(prefix)
		if stateErr != nil {
			return stateErr
		}
		if state.Previous == "-" {
			return errorf(CodeDenied, "rollback", "no previous release exists", nil)
		}
		if err := writeLifecyclePending(prefix, lifecyclePending{Operation: operation, Version: state.Previous}); err != nil {
			return err
		}
		if err := lifecycleContext(ctx, "rollback"); err != nil {
			return err
		}
		previous, openErr := prefix.OpenRoot("releases/" + state.Previous)
		if openErr != nil {
			return lifecycleFailure("rollback", openErr)
		}
		if _, err := verifyReleaseTree(ctx, previous, state.PreviousManifest); err != nil {
			previous.Close()
			return err
		}
		previous.Close()
		if err := writeInstallState(prefix, installState{Current: state.Previous, Previous: state.Current, CurrentManifest: state.PreviousManifest, PreviousManifest: state.CurrentManifest}, false); err != nil {
			return err
		}
		if err := lifecycleFault("rollback_after_state"); err != nil {
			return err
		}
		return removePending(prefix)
	case "remove":
		if source != nil || version != "" {
			return errorf(CodeInvalidInput, "remove", "remove accepts only a prefix", nil)
		}
		state, stateErr := readInstallState(prefix)
		if stateErr != nil {
			return stateErr
		}
		current, openErr := prefix.OpenRoot("releases/" + state.Current)
		if openErr != nil {
			return lifecycleFailure("remove", openErr)
		}
		if _, err := verifyReleaseTree(ctx, current, state.CurrentManifest); err != nil {
			current.Close()
			return err
		}
		current.Close()
		rootNames, readErr := fs.ReadDir(prefix.FS(), ".")
		if readErr != nil || !equalNames(rootNames, []string{".coh-install-root", "releases", "state"}) {
			return errorf(CodeDenied, "remove", "install root contains unexpected entries", readErr)
		}
		if err := writeLifecyclePending(prefix, lifecyclePending{Operation: operation, Version: state.Current}); err != nil {
			return err
		}
		if err := lifecycleContext(ctx, "remove"); err != nil {
			return err
		}
		if err := removeAllReleaseTrees(ctx, prefix); err != nil {
			return err
		}
		if err := lifecycleContext(ctx, "remove"); err != nil {
			return err
		}
		if err := syncRoot(prefix); err != nil {
			return err
		}
		if err := lifecycleFault("remove_after_releases"); err != nil {
			return err
		}
		if err := prefix.Remove("state"); err != nil {
			return lifecycleFailure("remove", err)
		}
		if err := prefix.Remove(".coh-install-root"); err != nil {
			return lifecycleFailure("remove", err)
		}
		return removePending(prefix)
	}
	return nil
}

func openPrivateRoot(path string) (*os.Root, error) {
	root, err := openRealRoot(path, "prefix")
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil || info.Mode().Perm() != 0o700 {
		root.Close()
		return nil, errorf(CodeDenied, "prefix", "prefix must have mode 0700", err)
	}
	return root, nil
}

func openRealRoot(path, field string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, errorf(CodeInvalidInput, field, "existing absolute real directory is required", nil)
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errorf(CodeDenied, field, "directory must be real", err)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return nil, errorf(CodeDenied, field, "directory contains a symlink or changed identity", err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, lifecycleFailure(field, err)
	}
	opened, statErr := root.Stat(".")
	after, afterErr := os.Lstat(path)
	if statErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		root.Close()
		return nil, errorf(CodeDenied, field, "directory identity changed while opening", errors.Join(statErr, afterErr))
	}
	return root, nil
}

func installRelease(ctx context.Context, prefix, source *os.Root, version, manifestDigest string) error {
	base := "releases/" + version
	if err := prefix.Mkdir(base, 0o700); err != nil {
		return errorf(CodeDenied, "install", "release version already exists", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = removeContainedRelease(context.Background(), prefix, version)
		}
	}()
	for _, directory := range []string{base + "/bin", base + "/share", base + "/share/coh"} {
		if err := prefix.Mkdir(directory, 0o700); err != nil {
			return lifecycleFailure("install", err)
		}
	}
	for _, name := range append(slices.Clone(installedFiles), "share/coh/release-files.sha256") {
		if err := lifecycleContext(ctx, "install"); err != nil {
			return err
		}
		mode := fs.FileMode(0o444)
		if strings.HasPrefix(name, "bin/") || name == "share/coh/install_release.sh" {
			mode = 0o555
		}
		if err := copyRootFile(ctx, source, name, prefix, base+"/"+name, mode); err != nil {
			return err
		}
	}
	installed, err := prefix.OpenRoot(base)
	if err != nil {
		return lifecycleFailure("install", err)
	}
	_, err = verifyReleaseTree(ctx, installed, manifestDigest)
	if err == nil {
		err = syncReleaseTree(installed)
	}
	installed.Close()
	if err != nil {
		return err
	}
	if err := syncRootPath(prefix, "releases"); err != nil {
		return err
	}
	complete = true
	return nil
}

func copyRootFile(ctx context.Context, source *os.Root, sourceName string, destination *os.Root, destinationName string, mode fs.FileMode) error {
	input, err := source.Open(sourceName)
	if err != nil {
		return lifecycleFailure("source", err)
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaximumFileSize {
		return errorf(CodeDenied, "source", "source file is unsafe or oversized", err)
	}
	output, err := destination.OpenFile(destinationName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return lifecycleFailure("install", err)
	}
	if _, err := io.Copy(output, &contextReader{ctx: ctx, reader: io.LimitReader(input, MaximumFileSize+1)}); err != nil {
		output.Close()
		if CodeOf(err) == CodeCanceled || CodeOf(err) == CodeTimeout {
			return err
		}
		return lifecycleFailure("install", err)
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return lifecycleFailure("install", err)
	}
	return output.Close()
}

func verifyReleaseTree(ctx context.Context, root *os.Root, expectedManifest string) (string, error) {
	if err := verifyTreeShape(root); err != nil {
		return "", err
	}
	manifest, err := root.ReadFile("share/coh/release-files.sha256")
	if err != nil || len(manifest) > 1<<20 {
		return "", lifecycleFailure("manifest", err)
	}
	sum := sha256.Sum256(manifest)
	manifestDigest := hex.EncodeToString(sum[:])
	if expectedManifest != "" && manifestDigest != expectedManifest {
		return "", errorf(CodeDenied, "manifest", "release digest inventory changed", nil)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(manifest)))
	index := 0
	for scanner.Scan() {
		if err := lifecycleContext(ctx, "verify"); err != nil {
			return "", err
		}
		if index >= len(installedFiles) {
			return "", errorf(CodeDenied, "manifest", "release digest inventory has extra entries", nil)
		}
		parts := strings.Split(scanner.Text(), "  ")
		if len(parts) != 2 || parts[1] != installedFiles[index] || !validDigest(parts[0]) {
			return "", errorf(CodeDenied, "manifest", "release digest inventory is malformed or unordered", nil)
		}
		file, openErr := root.Open(parts[1])
		if openErr != nil {
			return "", lifecycleFailure("release", openErr)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, &contextReader{ctx: ctx, reader: io.LimitReader(file, MaximumFileSize+1)})
		info, statErr := file.Stat()
		file.Close()
		if CodeOf(copyErr) == CodeCanceled || CodeOf(copyErr) == CodeTimeout {
			return "", copyErr
		}
		if copyErr != nil || statErr != nil || !info.Mode().IsRegular() || info.Size() > MaximumFileSize || hex.EncodeToString(hash.Sum(nil)) != parts[0] {
			return "", errorf(CodeDenied, "release", "release file digest or identity differs", errors.Join(copyErr, statErr))
		}
		index++
	}
	if scanner.Err() != nil || index != len(installedFiles) {
		return "", errorf(CodeDenied, "manifest", "release digest inventory cardinality differs", scanner.Err())
	}
	return manifestDigest, nil
}

func verifyTreeShape(root *os.Root) error {
	checks := map[string][]string{
		".":         {"bin", "share"},
		"bin":       {"archcheck", "installgate", "qualitygate"},
		"share":     {"coh"},
		"share/coh": {"LICENSE", "install_release.sh", "release-files.sha256"},
	}
	for directory, expected := range checks {
		entries, err := fs.ReadDir(root.FS(), directory)
		if err != nil || !equalNames(entries, expected) {
			return errorf(CodeDenied, "release", "release tree shape differs", err)
		}
	}
	return nil
}

func equalNames(entries []fs.DirEntry, expected []string) bool {
	if len(entries) != len(expected) {
		return false
	}
	for index, entry := range entries {
		if entry.Name() != expected[index] {
			return false
		}
	}
	return true
}
