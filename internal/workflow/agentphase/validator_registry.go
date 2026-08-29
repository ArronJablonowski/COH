package agentphase

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

const maximumValidationBytes = 4 << 20

type ValidatorRegistry struct {
	mu         sync.RWMutex
	validators map[string]ArtifactValidator
}

func NewValidatorRegistry() *ValidatorRegistry {
	registry := &ValidatorRegistry{validators: make(map[string]ArtifactValidator)}
	for _, profile := range []string{"workspace-v1", "json-v1", "python-v1", "sigma-v1", "spl-v1", "kql-v1",
		"esql-v1", "yaral-v1", "appsec-v1", "exploit-analysis-v1", "prompt-injection-v1"} {
		_ = registry.Register(&deterministicValidator{profile: profile, digest: canonicalDigest(struct {
			Profile string `json:"profile"`
			Version string `json:"version"`
		}{profile, "1.0.0"})})
	}
	return registry
}

func (registry *ValidatorRegistry) Register(validator ArtifactValidator) error {
	if registry == nil || validator == nil || !validToken(validator.ID()) || !validDigest(validator.Digest()) {
		return errors.New("validator registration is invalid")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.validators[validator.ID()]; exists {
		return errors.New("validator is already registered")
	}
	registry.validators[validator.ID()] = validator
	return nil
}

func (registry *ValidatorRegistry) Resolve(profile string) (ArtifactValidator, error) {
	if registry == nil || !validToken(profile) {
		return nil, errors.New("validator profile is invalid")
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	validator, exists := registry.validators[profile]
	if !exists {
		return nil, errors.New("validator profile is not allowlisted")
	}
	return validator, nil
}

type deterministicValidator struct {
	profile string
	digest  string
}

func (validator *deterministicValidator) ID() string     { return validator.profile }
func (validator *deterministicValidator) Digest() string { return validator.digest }

func (validator *deterministicValidator) Validate(ctx context.Context, contract TaskContract,
	candidate CandidateArtifact, attempt uint32, budget, previous string) (ValidationRecordV2, error) {
	if err := ctx.Err(); err != nil {
		return ValidationRecordV2{}, err
	}
	if err := contract.Validate(); err != nil || contract.ValidatorProfile != validator.profile {
		return ValidationRecordV2{}, errors.New("validator is not bound to the task contract")
	}
	content, files, readErr := validationContent(contract.Workspace, candidate.Text)
	evidence := []string{candidate.ArtifactDigest}
	checks := []ValidationCheck{{Code: "workspace_boundary", Mandatory: true, Passed: readErr == nil, EvidenceRefs: evidence},
		{Code: "artifact_nonempty", Mandatory: true, Passed: strings.TrimSpace(content) != "" || len(files) > 0, EvidenceRefs: evidence}}
	profileContent := content
	if validator.profile == "json-v1" {
		profileContent = candidate.Text
	}
	if profileCheck := validator.profileCheck(profileContent, files); profileCheck.Code != "" {
		profileCheck.EvidenceRefs = evidence
		checks = append(checks, profileCheck)
	}
	diagnostics := diagnosticsForChecks(checks, readErr)
	return NewValidationRecord(attempt, candidate.ArtifactDigest, validator.ID(), validator.Digest(), budget,
		previous, checks, diagnostics)
}

func (validator *deterministicValidator) profileCheck(content string, files []string) ValidationCheck {
	lower := strings.ToLower(content)
	check := ValidationCheck{Mandatory: true, Passed: true}
	switch validator.profile {
	case "json-v1":
		check.Code, check.Passed = "json_syntax", json.Valid([]byte(strings.TrimSpace(content)))
	case "python-v1":
		check.Code = "python_artifact"
		check.Passed = slices.ContainsFunc(files, func(name string) bool { return strings.HasSuffix(name, ".py") }) || strings.Contains(lower, "def ")
	case "sigma-v1":
		check.Code = "sigma_structure"
		check.Passed = containsAll(lower, "title:", "logsource:", "detection:", "condition:")
	case "spl-v1":
		check.Code, check.Passed = "spl_pipeline", strings.Contains(content, "|") && containsAny(lower, "stats", "where", "search")
	case "kql-v1":
		check.Code, check.Passed = "kql_pipeline", strings.Contains(content, "|") && containsAny(lower, "where", "summarize", "project")
	case "esql-v1":
		check.Code = "esql_pipeline"
		check.Passed = containsAny(lower, "from ", "row ") && strings.Contains(content, "|")
	case "yaral-v1":
		check.Code = "yaral_structure"
		check.Passed = containsAll(lower, "rule ", "meta:", "events:", "condition:")
	case "appsec-v1":
		check.Code = "appsec_artifact"
		check.Passed = len(files) > 0 && containsAny(lower, "test", "authorize", "permission", "validation")
	case "exploit-analysis-v1":
		check.Code = "exploit_scope"
		check.Passed = containsAny(lower, "root cause", "crash", "impact", "mitigation", "flag") && !containsAny(lower, "curl http", "wget http", "nc -")
	case "prompt-injection-v1":
		check.Code = "injection_controls"
		check.Passed = containsAny(lower, "untrusted", "approval", "deny", "allowlist", "provenance")
	default:
		check.Code, check.Passed = "workspace_artifact", len(files) > 0 || strings.TrimSpace(content) != ""
	}
	return check
}

func validationContent(root, modelText string) (string, []string, error) {
	rootInfo, err := os.Stat(root)
	if err != nil || !rootInfo.IsDir() {
		return modelText, nil, errors.New("workspace is unavailable")
	}
	var content strings.Builder
	content.WriteString(modelText)
	files := []string{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("workspace contains a symbolic link")
		}
		if entry.IsDir() {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || strings.HasPrefix(relative, "..") {
			return errors.New("workspace path escaped its root")
		}
		files = append(files, filepath.ToSlash(relative))
		if content.Len() >= maximumValidationBytes {
			return nil
		}
		value, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		remaining := maximumValidationBytes - content.Len()
		if len(value) > remaining {
			value = value[:remaining]
		}
		content.WriteByte('\n')
		content.Write(value)
		return nil
	})
	slices.Sort(files)
	return content.String(), files, err
}

func diagnosticsForChecks(checks []ValidationCheck, readErr error) []ValidationDiagnostic {
	diagnostics := []ValidationDiagnostic{}
	for _, check := range checks {
		if check.Passed {
			continue
		}
		message := map[string]string{"workspace_boundary": "Keep all files inside the assigned workspace and remove symbolic links.",
			"artifact_nonempty":  "Produce the requested artifact instead of only describing future work.",
			"json_syntax":        "Return one valid JSON value with no Markdown fence or surrounding prose.",
			"python_artifact":    "Create or revise the requested Python implementation and tests.",
			"sigma_structure":    "Include valid Sigma title, logsource, detection, and condition sections.",
			"spl_pipeline":       "Produce an executable SPL search with an explicit pipeline and filtering or aggregation.",
			"kql_pipeline":       "Produce executable KQL with an explicit pipeline and filtering, projection, or aggregation.",
			"esql_pipeline":      "Produce executable ES|QL beginning with a source and using a pipeline.",
			"yaral_structure":    "Produce a YARA-L rule with meta, events, and condition sections.",
			"appsec_artifact":    "Implement the security repair and include verification for authorization or input handling.",
			"exploit_scope":      "Keep exploit analysis within the toy workspace and include root cause, impact, and mitigation or proof.",
			"injection_controls": "Document or implement explicit untrusted-input, approval, allowlist, or provenance controls.",
			"workspace_artifact": "Create the requested workspace artifact."}[check.Code]
		if check.Code == "workspace_boundary" && readErr != nil {
			message = "The workspace failed deterministic boundary validation; keep artifacts inside the assigned root."
		}
		diagnostics = append(diagnostics, ValidationDiagnostic{Code: check.Code, Message: message, EvidenceRefs: check.EvidenceRefs})
	}
	return diagnostics
}

func containsAll(value string, tokens ...string) bool {
	return !slices.ContainsFunc(tokens, func(token string) bool { return !strings.Contains(value, token) })
}

func containsAny(value string, tokens ...string) bool {
	return slices.ContainsFunc(tokens, func(token string) bool { return strings.Contains(value, token) })
}
