package architecture

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

var (
	buildTagPattern = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
)

// ParseBuildTags validates, deduplicates, and sorts a comma-separated Go build
// tag set so the compiler invocation and evidence report use identical input.
func ParseBuildTags(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{}, nil
	}
	tags := strings.Split(raw, ",")
	for index := range tags {
		tags[index] = strings.TrimSpace(tags[index])
		if !buildTagPattern.MatchString(tags[index]) {
			return nil, contractError(CodeInvalidInput, "tags", "invalid Go build tag", nil)
		}
	}
	slices.Sort(tags)
	return slices.Compact(tags), nil
}

// RuntimeProvenance captures the actual checker, toolchain, and target rather
// than assuming the contract baseline describes the running process.
func RuntimeProvenance(buildTags []string) Provenance {
	return Provenance{
		SourceDigest: "not_collected", InputDigest: "not_collected", VCSRevision: "not_collected",
		CheckerVersion: CheckerVersion, GoVersion: runtime.Version(),
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		BuildTags: slices.Clone(buildTags),
	}
}

// AddVCSProvenance records Git revision and dirty state without making Git a
// prerequisite. An unborn or unavailable repository remains explicitly dirty.
func AddVCSProvenance(ctx context.Context, root string, provenance *Provenance) {
	provenance.VCSRevision = "unavailable"
	provenance.VCSModified = true
	command := exec.CommandContext(ctx, "git", "rev-parse", "--verify", "HEAD")
	command.Dir = root
	var revision limitedBuffer
	revision.remaining = 256
	command.Stdout = &revision
	if err := command.Run(); err != nil {
		var execErr *exec.Error
		if !errors.As(err, &execErr) {
			provenance.VCSRevision = "unborn"
		}
		return
	}
	value := strings.TrimSpace(revision.String())
	if !revisionPattern.MatchString(value) {
		return
	}
	provenance.VCSRevision = value

	status := exec.CommandContext(ctx, "git", "status", "--porcelain=v1", "--untracked-files=normal")
	status.Dir = root
	var output limitedBuffer
	output.remaining = 1 << 20
	status.Stdout = &output
	if err := status.Run(); err != nil {
		return
	}
	provenance.VCSModified = strings.TrimSpace(output.String()) != ""
}
