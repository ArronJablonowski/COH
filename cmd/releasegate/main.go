// Command releasegate assembles and verifies the bounded COH native release contract.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/quality"
	"github.com/ArronJablonowski/COH/internal/helper/supplychain"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("releasegate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	mode := flags.String("mode", "verify", "operation: assemble or verify")
	root := flags.String("root", ".", "repository root")
	policyPath := flags.String("policy", "ci/release-policy.json", "release policy path")
	bundle := flags.String("bundle", "", "fresh output or existing bundle directory")
	target := flags.String("target", runtime.GOOS+"/"+runtime.GOARCH, "release target")
	goBinary := flags.String("go-binary", os.Getenv("COH_GO_BIN"), "pinned Go binary")
	role := flags.String("role", "ci-fixture", "signing authority: ci-fixture or release")
	signingKey := flags.String("signing-key", "", "release-role PKCS#8 Ed25519 private key")
	timeout := flags.Duration("timeout", 10*time.Minute, "operation deadline")
	if err := flags.Parse(arguments); err != nil {
		return 64
	}
	if flags.NArg() != 0 || (*mode != "assemble" && *mode != "verify") ||
		(*role != "ci-fixture" && *role != "release") || *bundle == "" || *goBinary == "" || *timeout <= 0 {
		fmt.Fprintln(stderr, "invalid arguments")
		return 64
	}
	if *mode == "assemble" && *role == "release" && *signingKey == "" {
		fmt.Fprintln(stderr, "release assembly requires -signing-key")
		return 64
	}
	if *signingKey != "" && (*mode != "assemble" || *role != "release") {
		fmt.Fprintln(stderr, "signing-key is accepted only for release assembly")
		return 64
	}
	rootPath, err := filepath.Abs(*root)
	if err != nil {
		return printFailure(stderr, &supplychain.Error{Code: supplychain.CodeInvalidInput, Field: "root", Detail: "cannot resolve root", Cause: err})
	}
	policy, policyDigest, err := supplychain.ReadPolicy(filepath.Join(rootPath, filepath.FromSlash(*policyPath)))
	if err != nil {
		return printFailure(stderr, err)
	}
	if !slices.Contains(policy.Targets, *target) || !slices.Contains(policy.GoVersions, runtime.Version()) {
		return printFailure(stderr, &supplychain.Error{Code: supplychain.CodeDenied, Field: "policy", Detail: "target or Go version is not approved"})
	}
	bundlePath, err := filepath.Abs(*bundle)
	if err != nil {
		return printFailure(stderr, &supplychain.Error{Code: supplychain.CodeInvalidInput, Field: "bundle", Detail: "cannot resolve bundle", Cause: err})
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, *timeout)
	defer cancel()
	snapshot, err := quality.SnapshotWorkspace(ctx, rootPath)
	if err != nil {
		return printFailure(stderr, err)
	}
	toolchain, err := supplychain.FileArtifact(*goBinary, "go")
	if err != nil {
		return printFailure(stderr, err)
	}
	source := supplychain.Artifact{Path: "source", SHA256: snapshot.Digest, Length: int64(snapshot.FileCount)}
	policyArtifact := supplychain.Artifact{Path: "release-policy", SHA256: policyDigest}
	trusted, err := supplychain.LoadTrustedKey(rootPath, policy, *role)
	if err != nil {
		return printFailure(stderr, err)
	}
	builderID := selectBuilder(policy, *role, os.Getenv("CI") == "true")
	if *mode == "assemble" {
		if *role == "release" && !supplychain.ReleaseGoBinaryApproved(policy, toolchain, runtime.Version()) {
			return printFailure(stderr, &supplychain.Error{Code: supplychain.CodeDenied, Field: "go_binary", Detail: "release compiler digest is not approved"})
		}
		var privateKey []byte
		if *role == "release" {
			privateKey, err = supplychain.ReadPrivateKey(*signingKey)
			if err != nil {
				return printFailure(stderr, err)
			}
		} else {
			var fixture supplychain.TrustedKey
			privateKey, fixture, err = supplychain.CIFixtureKey()
			if err != nil {
				return printFailure(stderr, err)
			}
			if fixture.KeyID != trusted.KeyID {
				return printFailure(stderr, &supplychain.Error{Code: supplychain.CodeDenied, Field: "fixture_key", Detail: "derived fixture key differs from policy"})
			}
		}
		if err := supplychain.VerifyPrivateKeyAuthority(privateKey, trusted); err != nil {
			return printFailure(stderr, err)
		}
		inputs, cleanup, inputErr := buildArchiveInputs(ctx, rootPath, *goBinary, policy.Archive)
		if inputErr != nil {
			return printFailure(stderr, inputErr)
		}
		defer cleanup()
		_, err = supplychain.AssembleBundle(ctx, supplychain.BundleRequest{
			OutputDirectory: bundlePath, Version: policy.ReleaseVersion, Target: *target,
			GoVersion: runtime.Version(), BuilderID: builderID, Revision: snapshot.VCSRevision,
			Source: source, Toolchain: toolchain, Policy: policyArtifact,
			PrivateKeyPEM: privateKey, Role: *role, ArchiveInputs: inputs,
		})
	} else {
		_, err = supplychain.VerifyBundle(ctx, supplychain.VerifyRequest{
			Directory: bundlePath, Version: policy.ReleaseVersion, Target: *target,
			GoVersion: runtime.Version(), BuilderID: builderID, Revision: snapshot.VCSRevision,
			Source: source, Toolchain: toolchain, Policy: policyArtifact,
			TrustedKey: trusted, ArchiveContents: policy.Archive,
		})
	}
	if err != nil {
		return printFailure(stderr, err)
	}
	fmt.Fprintf(stdout, "releasegate %s: passed\n", *mode)
	return 0
}

func selectBuilder(policy supplychain.Policy, role string, hosted bool) string {
	if role == "ci-fixture" && hosted {
		return policy.BuilderIDs[0]
	}
	return policy.BuilderIDs[1]
}

func buildArchiveInputs(ctx context.Context, root, goBinary string, requirements []supplychain.ArchiveRequirement) ([]supplychain.ArchiveInput, func(), error) {
	stage, err := os.MkdirTemp(os.Getenv("GOTMPDIR"), "coh-release-build-*")
	if err != nil {
		return nil, func() {}, &supplychain.Error{Code: supplychain.CodeToolFailure, Field: "build", Detail: "cannot create private build directory", Cause: err}
	}
	cleanup := func() { _ = os.RemoveAll(stage) }
	if err := os.Chmod(stage, 0o700); err != nil {
		cleanup()
		return nil, func() {}, &supplychain.Error{Code: supplychain.CodeToolFailure, Field: "build", Detail: "cannot protect build directory", Cause: err}
	}
	sources := make(map[string]string, len(requirements))
	for _, requirement := range requirements {
		switch requirement.Path {
		case "bin/archcheck", "bin/installgate", "bin/qualitygate":
			source := filepath.Join(stage, filepath.Base(requirement.Path))
			command := exec.CommandContext(ctx, goBinary, "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", source, requirement.Package)
			command.Dir = root
			command.Env = append(os.Environ(), "CGO_ENABLED=0")
			if output, buildErr := command.CombinedOutput(); buildErr != nil {
				cleanup()
				if ctx.Err() != nil {
					code := supplychain.CodeCanceled
					if errors.Is(ctx.Err(), context.DeadlineExceeded) {
						code = supplychain.CodeTimeout
					}
					return nil, func() {}, &supplychain.Error{Code: code, Field: "build", Detail: "release build interrupted", Cause: ctx.Err()}
				}
				_ = output
				return nil, func() {}, &supplychain.Error{Code: supplychain.CodeToolFailure, Field: "build", Detail: "fixed release build failed", Cause: buildErr}
			}
			sources[requirement.Path] = source
		case "share/coh/LICENSE":
			sources[requirement.Path] = filepath.Join(root, "LICENSE")
		case "share/coh/install_release.sh":
			sources[requirement.Path] = filepath.Join(root, "scripts", "install_release.sh")
		case "share/coh/release-files.sha256":
		default:
			cleanup()
			return nil, func() {}, &supplychain.Error{Code: supplychain.CodeDenied, Field: "policy.archive", Detail: "unsupported archive source"}
		}
	}
	manifestNames := make([]string, 0, len(sources))
	for name := range sources {
		manifestNames = append(manifestNames, name)
	}
	sort.Strings(manifestNames)
	var manifest strings.Builder
	for _, name := range manifestNames {
		artifact, artifactErr := supplychain.FileArtifact(sources[name], filepath.Base(name))
		if artifactErr != nil {
			cleanup()
			return nil, func() {}, artifactErr
		}
		fmt.Fprintf(&manifest, "%s  %s\n", artifact.SHA256, name)
	}
	manifestPath := filepath.Join(stage, "release-files.sha256")
	if err := os.WriteFile(manifestPath, []byte(manifest.String()), 0o400); err != nil {
		cleanup()
		return nil, func() {}, &supplychain.Error{Code: supplychain.CodeToolFailure, Field: "build", Detail: "cannot write release file inventory", Cause: err}
	}
	sources["share/coh/release-files.sha256"] = manifestPath
	inputs := make([]supplychain.ArchiveInput, 0, len(requirements))
	for _, requirement := range requirements {
		inputs = append(inputs, supplychain.ArchiveInput{Source: sources[requirement.Path], Path: requirement.Path, Mode: requirement.Mode, Package: requirement.Package})
	}
	return inputs, cleanup, nil
}

func printFailure(writer io.Writer, err error) int {
	var typed *supplychain.Error
	if !errors.As(err, &typed) {
		fmt.Fprintln(writer, "releasegate: tool_failure")
		return 1
	}
	field := strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character) {
			return character
		}
		return -1
	}, typed.Field)
	fmt.Fprintf(writer, "releasegate: %s: %s\n", typed.Code, field)
	switch typed.Code {
	case supplychain.CodeInvalidInput:
		return 64
	case supplychain.CodeDenied:
		return 2
	default:
		return 1
	}
}
