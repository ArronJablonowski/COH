package quality

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/filesize"
)

const maximumArtifactSize = 64 << 20

var stageArtifactNames = map[string][]string{
	"format":           {"format.log"},
	"file-size":        {"file-size.log", "file-size-report.json"},
	"vet":              {"vet.log"},
	"static-analysis":  {"static-analysis.log"},
	"unit":             {"unit.log"},
	"race":             {"race.log"},
	"fuzz-seed":        {"fuzz-seed.log"},
	"architecture":     {"architecture.log", "architecture-report.json"},
	"quality-contract": {"quality-contract.log"},
	"workflow":         {"workflow.log"},
	"secret-worktree":  {"secret-worktree.log"},
	"secret-history":   {"secret-history.log"},
	"license":          {"license.log"},
	"dependency":       {"dependency.log", "govulncheck.sarif", "govulndb-verification.json"},
	"sbom":             {"sbom.log", "coh.cdx.json"},
	"supply-chain":     {"supply-chain.log"},
	"secret-evidence":  {"secret-evidence.log"},
	"provenance":       {"provenance.log", "ci-provenance.json"},
}

func StageEvidence(directory, stage string) ([]string, error) {
	names, ok := stageArtifactNames[stage]
	if !ok {
		return nil, qualityError(CodeDenied, "artifacts", "unknown stage artifact set", nil)
	}
	evidence := make([]string, 0, len(names))
	for _, name := range names {
		if err := verifyStageArtifact(directory, stage, name); err != nil {
			return nil, err
		}
		evidence = append(evidence, name)
	}
	return evidence, nil
}

func verifyStageArtifact(directory, stage, name string) error {
	if _, err := digestArtifact(directory, name); err != nil {
		return err
	}
	if stage == "file-size" && name == "file-size-report.json" {
		report, err := filesize.ReadAndVerifyReport(filepath.Join(directory, name))
		if err != nil || report.Outcome != "passed" || !report.ScanComplete {
			return qualityError(CodeDenied, "artifacts.file-size-report.json", "file-size evidence is invalid or non-passing", err)
		}
	}
	return nil
}

func captureFailureEvidence(directory, stage string, exitCode int, code ErrorCode) FailureEvidence {
	names := stageArtifactNames[stage]
	expected := ""
	if len(names) > 0 {
		expected = names[0]
	}
	evidence := FailureEvidence{Expected: expected, Status: "missing", ExitCode: exitCode}
	if code == CodeTimeout || code == CodeCanceled {
		evidence.Status = "incomplete"
	}
	if expected == "" {
		evidence.Status = "unsafe"
		return evidence
	}
	artifact, err := digestArtifact(directory, expected)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(directory, expected)); statErr == nil {
			evidence.Status = "unsafe"
		}
		return evidence
	}
	evidence.Artifact = &artifact
	if code != CodeTimeout && code != CodeCanceled {
		evidence.Status = "present"
	}
	return evidence
}

func digestArtifact(directory, name string) (Artifact, error) {
	if filepath.Base(name) != name || name == "." {
		return Artifact{}, qualityError(CodeDenied, "artifact", "unsafe artifact name", nil)
	}
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil {
		return Artifact{}, qualityError(CodeToolFailure, "artifact", "required artifact is missing: "+name, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maximumArtifactSize {
		return Artifact{}, qualityError(CodeDenied, "artifact", "artifact is not a bounded regular file: "+name, nil)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, qualityError(CodeToolFailure, "artifact", "cannot read artifact: "+name, err)
	}
	sum := sha256.Sum256(data)
	return Artifact{Path: name, SHA256: hex.EncodeToString(sum[:]), Length: int64(len(data))}, nil
}

// DigestFile returns SHA-256 for a bounded regular file without exposing its
// contents. It is used by shell gates that must remain platform-neutral.
func DigestFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximumArtifactSize {
		return "", qualityError(CodeDenied, "digest", "input must be a bounded regular file", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", qualityError(CodeToolFailure, "digest", "cannot read input", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// WriteReportAtomic canonicalizes the report digest, fsyncs a sibling temporary
// file, and renames only after a complete write.
func WriteReportAtomic(path string, report *Report) error {
	report.ReportDigest = ""
	canonical, err := json.Marshal(report)
	if err != nil {
		return qualityError(CodeToolFailure, "report", "cannot canonicalize report", err)
	}
	sum := sha256.Sum256(canonical)
	report.ReportDigest = hex.EncodeToString(sum[:])
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return qualityError(CodeToolFailure, "report", "cannot encode report", err)
	}
	encoded = append(encoded, '\n')
	return writeAtomic(path, encoded)
}

// ReadAndVerifyReport rejects truncation, extension fields, and self-digest
// tampering before an on-disk report is trusted as final evidence.
func ReadAndVerifyReport(path string) (Report, error) {
	data, err := readBoundedRegular(path, maximumArtifactSize)
	if err != nil {
		return Report{}, err
	}
	var report Report
	if err := decodeStrict(data, &report); err != nil {
		return Report{}, qualityError(CodeDenied, "report", "invalid report encoding", err)
	}
	if report.SchemaVersion != ReportSchema || report.ReportVersion != ReportVersion {
		return Report{}, qualityError(CodeDenied, "report", "unsupported report contract", nil)
	}
	expected := report.ReportDigest
	report.ReportDigest = ""
	canonical, err := json.Marshal(report)
	if err != nil {
		return Report{}, qualityError(CodeToolFailure, "report", "cannot canonicalize report", err)
	}
	sum := sha256.Sum256(canonical)
	report.ReportDigest = expected
	if expected == "" || expected != hex.EncodeToString(sum[:]) {
		return Report{}, qualityError(CodeDenied, "report", "report digest mismatch", nil)
	}
	if err := validateReportSemantics(report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func validateReportSemantics(report Report) error {
	if report.Issue != qualityIssue || !slices.Equal(report.Requirements, provenanceRequirements) {
		return qualityError(CodeDenied, "report", "report traceability differs from the closed contract", nil)
	}
	if report.Verification == nil || (report.Verification.Outcome == "passed" && report.Verification.FailureCode != "") ||
		(report.Verification.Outcome != "passed" && (report.Verification.FailureCode == "" || report.Verification.Outcome != outcomeFor(report.Verification.FailureCode))) {
		return qualityError(CodeDenied, "report", "terminal source verification is inconsistent", nil)
	}
	if !slices.Contains(requiredLanes, report.Lane) || report.Provenance.GoVersion != "go"+report.Lane.GoVersion ||
		report.Provenance.GOOS == "" || report.Provenance.GOARCH == "" || report.Provenance.SourceFiles < 1 ||
		!validDigest(report.Provenance.PolicyDigest) || !validDigest(report.Provenance.ToolLockDigest) ||
		!validDigest(report.Provenance.SourceDigest) || !validRevision(report.Provenance.VCSRevision) {
		return qualityError(CodeDenied, "report", "report provenance is incomplete or invalid", nil)
	}
	if report.QualityGatePromotable && (report.Outcome != "passed" || report.Lane.Enforcement != "required" ||
		report.Provenance.VCSRevision == "unborn" || report.Provenance.VCSModified) {
		return qualityError(CodeDenied, "report", "quality-gate promotability contradicts provenance", nil)
	}
	if len(report.Stages) == 0 || len(report.Stages) > len(requiredStages) {
		return qualityError(CodeDenied, "report", "stage trajectory is incomplete", nil)
	}
	terminalFailure := false
	for index, stage := range report.Stages {
		if stage.ID != requiredStages[index] || stage.CommandDigest != commandDigest(stage.ID) {
			return qualityError(CodeDenied, "report", "stage identity, order, or command digest differs", nil)
		}
		switch stage.Outcome {
		case "passed":
			if stage.FailureCode != "" || stage.Note != "" || stage.FailureEvidence != nil || !slices.Equal(stage.Evidence, stageArtifactNames[stage.ID]) {
				return qualityError(CodeDenied, "report", "passed stage evidence differs", nil)
			}
		case "skipped":
			if report.Lane.ID != "go1.27" || stage.ID != "static-analysis" || stage.FailureCode != "" || stage.FailureEvidence != nil || len(stage.Evidence) != 0 ||
				stage.Note != "Staticcheck 2026.1 is not qualified for Go 1.27; lane remains required-to-pass and non-promoting" {
				return qualityError(CodeDenied, "report", "unsupported stage skip", nil)
			}
		default:
			if index != len(report.Stages)-1 || len(stage.Evidence) != 0 || stage.Note != "" ||
				stage.FailureCode == "" || stage.Outcome != outcomeFor(stage.FailureCode) || !validFailureEvidence(stage) {
				return qualityError(CodeDenied, "report", "invalid failed stage trajectory", nil)
			}
			terminalFailure = true
		}
	}
	if terminalFailure {
		last := report.Stages[len(report.Stages)-1]
		if report.Outcome != last.Outcome || report.FailureCode != last.FailureCode || report.QualityGatePromotable {
			return qualityError(CodeDenied, "report", "overall verdict differs from failed stage", nil)
		}
		return nil
	}
	if len(report.Stages) != len(requiredStages) {
		return qualityError(CodeDenied, "report", "successful stage prefix is not a final verdict", nil)
	}
	if report.Outcome == "passed" {
		if report.FailureCode != "" || report.Verification.Outcome != "passed" {
			return qualityError(CodeDenied, "report", "passed report carries a failure code", nil)
		}
		return nil
	}
	if report.QualityGatePromotable || report.FailureCode == "" || report.Outcome != outcomeFor(report.FailureCode) ||
		report.Verification.Outcome != report.Outcome || report.Verification.FailureCode != report.FailureCode {
		return qualityError(CodeDenied, "report", "post-stage verification failure is inconsistent", nil)
	}
	return nil
}

func validFailureEvidence(stage StageResult) bool {
	if stage.FailureEvidence == nil || len(stageArtifactNames[stage.ID]) == 0 ||
		stage.FailureEvidence.Expected != stageArtifactNames[stage.ID][0] {
		return false
	}
	switch stage.FailureEvidence.Status {
	case "present":
		return stage.FailureCode != CodeTimeout && stage.FailureCode != CodeCanceled && validFailureArtifact(stage.FailureEvidence)
	case "incomplete":
		return (stage.FailureCode == CodeTimeout || stage.FailureCode == CodeCanceled) &&
			(stage.FailureEvidence.Artifact == nil || validFailureArtifact(stage.FailureEvidence))
	case "missing", "unsafe":
		return stage.FailureEvidence.Artifact == nil
	default:
		return false
	}
}

func validFailureArtifact(evidence *FailureEvidence) bool {
	return evidence.Artifact != nil && evidence.Artifact.Path == evidence.Expected && evidence.Artifact.Length >= 0 && validDigest(evidence.Artifact.SHA256)
}

func validRevision(value string) bool {
	if value == "unborn" {
		return true
	}
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, qualityError(CodeDenied, "artifact", "input must be a bounded regular file", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, qualityError(CodeToolFailure, "artifact", "cannot read input", err)
	}
	return data, nil
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return qualityError(CodeToolFailure, "output", "cannot create output directory", err)
	}
	temporary, err := os.CreateTemp(directory, ".coh-atomic-*")
	if err != nil {
		return qualityError(CodeToolFailure, "output", "cannot create temporary output", err)
	}
	temporaryPath := temporary.Name()
	complete := false
	defer func() {
		_ = temporary.Close()
		if !complete {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o640); err != nil {
		return qualityError(CodeToolFailure, "output", "cannot set output mode", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return qualityError(CodeToolFailure, "output", "cannot write complete output", err)
	}
	if err := temporary.Sync(); err != nil {
		return qualityError(CodeToolFailure, "output", "cannot sync output", err)
	}
	if err := temporary.Close(); err != nil {
		return qualityError(CodeToolFailure, "output", "cannot close output", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return qualityError(CodeToolFailure, "output", "cannot publish output", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return qualityError(CodeToolFailure, "output", "cannot open output directory for sync", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		_ = directoryHandle.Close()
		return qualityError(CodeToolFailure, "output", "cannot sync output directory", err)
	}
	if err := directoryHandle.Close(); err != nil {
		return qualityError(CodeToolFailure, "output", "cannot close output directory", err)
	}
	complete = true
	return nil
}

type goModule struct {
	Path    string
	Version string
	Main    bool
}

type cyclonedxBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Metadata     cyclonedxMetadata    `json:"metadata"`
	Components   []cyclonedxComponent `json:"components"`
}

type cyclonedxMetadata struct {
	Component cyclonedxComponent `json:"component"`
}

type cyclonedxComponent struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

func GenerateSBOM(ctx context.Context, root, output string) error {
	modules, err := listModules(ctx, root)
	if err != nil {
		return err
	}
	components := make([]cyclonedxComponent, 0, len(modules))
	var rootComponent cyclonedxComponent
	for _, module := range modules {
		version := module.Version
		if version == "" {
			version = "devel"
		}
		purl := "pkg:golang/" + strings.ReplaceAll(url.PathEscape(module.Path), "%2F", "/") + "@" + url.PathEscape(version)
		component := cyclonedxComponent{Type: "library", BOMRef: purl, Name: module.Path, Version: version, PURL: purl}
		if module.Main {
			component.Type = "application"
			rootComponent = component
		} else {
			components = append(components, component)
		}
	}
	if rootComponent.Name == "" {
		return qualityError(CodeDenied, "sbom", "module inventory has no main module", nil)
	}
	slices.SortFunc(components, func(a, b cyclonedxComponent) int { return strings.Compare(a.PURL, b.PURL) })
	identity, _ := json.Marshal(append([]cyclonedxComponent{rootComponent}, components...))
	bom := cyclonedxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", SerialNumber: deterministicUUID(identity), Version: 1, Metadata: cyclonedxMetadata{Component: rootComponent}, Components: components}
	encoded, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return qualityError(CodeToolFailure, "sbom", "cannot encode CycloneDX document", err)
	}
	return writeAtomic(output, append(encoded, '\n'))
}

func listModules(ctx context.Context, root string) ([]goModule, error) {
	command := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-json", "all")
	command.Dir = root
	var output boundedBuffer
	output.remaining = maximumArtifactSize
	command.Stdout = &output
	var diagnostic boundedBuffer
	diagnostic.remaining = 1 << 20
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, contextQualityError(ctxErr, "sbom")
		}
		return nil, qualityError(CodeToolFailure, "sbom", "go module inventory failed", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output.Bytes())))
	var modules []goModule
	for {
		var module goModule
		if err := decoder.Decode(&module); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, qualityError(CodeToolFailure, "sbom", "invalid module inventory", err)
		}
		modules = append(modules, module)
	}
	return modules, nil
}

func deterministicUUID(input []byte) string {
	sum := sha256.Sum256(input)
	bytes := sum[:16]
	bytes[6] = (bytes[6] & 0x0f) | 0x50
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}
