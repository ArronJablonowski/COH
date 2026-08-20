package architecture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

var versionPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

var requiredBoundaries = map[string]Boundary{
	"command": {
		Roots: []string{"cmd", "internal/command"},
		MayImport: []string{
			"broker", "command", "domain", "helper", "persistence",
			"provider", "transport", "ui", "workflow",
		},
	},
	"broker": {
		Roots: []string{"cmd/coh-brokerd", "internal/broker"},
		MayImport: []string{
			"broker", "connector", "domain", "helper", "policy", "workflow",
		},
	},
	"domain":      {Roots: []string{"internal/domain"}, MayImport: []string{"domain", "helper"}},
	"policy":      {Roots: []string{"internal/policy"}, MayImport: []string{"domain", "helper", "policy"}},
	"workflow":    {Roots: []string{"internal/workflow"}, MayImport: []string{"domain", "helper", "workflow"}},
	"provider":    {Roots: []string{"internal/provider"}, MayImport: []string{"domain", "helper", "provider", "workflow"}},
	"connector":   {Roots: []string{"internal/connector"}, MayImport: []string{"connector", "domain", "helper"}},
	"persistence": {Roots: []string{"internal/persistence"}, MayImport: []string{"domain", "helper", "persistence", "workflow"}},
	"transport":   {Roots: []string{"internal/transport"}, MayImport: []string{"domain", "helper", "transport", "ui", "workflow"}},
	"ui":          {Roots: []string{"internal/ui"}, MayImport: []string{"helper", "ui"}},
	"helper":      {Roots: []string{"internal/helper"}, MayImport: []string{"helper"}},
}

// DecodeContract strictly parses and semantically validates a workspace
// contract. Unknown fields and trailing JSON are rejected.
func DecodeContract(data []byte) (Contract, error) {
	if len(data) == 0 {
		return Contract{}, contractError(CodeInvalidInput, "$", "contract is empty", nil)
	}
	if len(data) > MaximumContractSize {
		return Contract{}, contractError(CodeInvalidInput, "$", "contract exceeds 1 MiB", nil)
	}

	var contract Contract
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, contractError(CodeInvalidInput, "$", "invalid contract JSON", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Contract{}, contractError(CodeInvalidInput, "$", "trailing JSON is forbidden", err)
	}
	if err := ValidateContract(contract); err != nil {
		return Contract{}, err
	}
	return contract, nil
}

// ValidateContract enforces the v1 schema and locked dependency policy.
func ValidateContract(contract Contract) error {
	if contract.SchemaVersion != SchemaVersion {
		return contractError(CodeUnsupportedVersion, "schema_version", "unsupported schema version", nil)
	}
	if err := validateVersion(contract.ContractVersion); err != nil {
		return err
	}
	if contract.Canonicalization != Canonicalization {
		return contractError(CodeUnsupportedVersion, "canonicalization", "unsupported canonicalization", nil)
	}
	if contract.GoBaseline != BaselineGoVersion {
		return contractError(CodeUnsupportedVersion, "go_baseline", "baseline must be Go 1.26.7", nil)
	}
	if contract.Module != ModulePath {
		return contractError(CodeInvalidInput, "module", "unexpected module path", nil)
	}
	if len(contract.Boundaries) != len(requiredBoundaries) {
		return contractError(CodeInvalidInput, "boundaries", "exactly eleven production boundaries are required", nil)
	}

	seen := make(map[string]struct{}, len(contract.Boundaries))
	rootOwner := make(map[string]string)
	for index, boundary := range contract.Boundaries {
		field := fmt.Sprintf("boundaries[%d]", index)
		expected, ok := requiredBoundaries[boundary.Name]
		if !ok {
			return contractError(CodeInvalidInput, field+".name", "unknown boundary", nil)
		}
		if _, duplicate := seen[boundary.Name]; duplicate {
			return contractError(CodeInvalidInput, field+".name", "duplicate boundary", nil)
		}
		seen[boundary.Name] = struct{}{}
		if strings.TrimSpace(boundary.Purpose) == "" {
			return contractError(CodeInvalidInput, field+".purpose", "purpose is required", nil)
		}
		if utf8.RuneCountInString(boundary.Purpose) > 240 {
			return contractError(CodeInvalidInput, field+".purpose", "purpose exceeds 240 characters", nil)
		}
		if !sameStrings(boundary.Roots, expected.Roots) {
			return contractError(CodeDenied, field+".roots", "roots differ from the locked v1 policy", nil)
		}
		if !sameStrings(boundary.MayImport, expected.MayImport) {
			return contractError(CodeDenied, field+".may_import", "imports differ from the locked v1 policy", nil)
		}
		for _, root := range boundary.Roots {
			if !validRoot(root) {
				return contractError(CodeInvalidInput, field+".roots", "root must be a clean relative directory", nil)
			}
			if owner, duplicate := rootOwner[root]; duplicate {
				return contractError(CodeInvalidInput, field+".roots", "root already owned by "+owner, nil)
			}
			rootOwner[root] = boundary.Name
		}
	}
	return nil
}

func validateVersion(version string) error {
	parts := versionPattern.FindStringSubmatch(version)
	if len(parts) != 4 {
		return contractError(CodeInvalidInput, "contract_version", "expected semantic version", nil)
	}
	if parts[1] != "1" || parts[2] != "0" {
		return contractError(CodeUnsupportedVersion, "contract_version", "reader supports 1.0.x only", nil)
	}
	return nil
}

func sameStrings(actual, expected []string) bool {
	a := slices.Clone(actual)
	b := slices.Clone(expected)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func validRoot(root string) bool {
	return root != "" && root != "." && !strings.HasPrefix(root, "/") &&
		!strings.HasSuffix(root, "/") && !strings.Contains(root, "..") &&
		!strings.Contains(root, "//")
}

// CanonicalBytes implements COH-JSON-C14N-1 for this closed schema: fields
// retain schema order, boundaries and string sets sort lexically, insignificant
// whitespace is removed, and no trailing newline is emitted.
func CanonicalBytes(contract Contract) ([]byte, error) {
	if err := ValidateContract(contract); err != nil {
		return nil, err
	}
	normalized := contract
	normalized.Boundaries = slices.Clone(contract.Boundaries)
	for index := range normalized.Boundaries {
		normalized.Boundaries[index].Roots = slices.Clone(normalized.Boundaries[index].Roots)
		normalized.Boundaries[index].MayImport = slices.Clone(normalized.Boundaries[index].MayImport)
		slices.Sort(normalized.Boundaries[index].Roots)
		slices.Sort(normalized.Boundaries[index].MayImport)
	}
	slices.SortFunc(normalized.Boundaries, func(a, b Boundary) int {
		return strings.Compare(a.Name, b.Name)
	})
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, contractError(CodeInvalidInput, "$", "canonical encoding failed", err)
	}
	return encoded, nil
}

// Digest returns the lowercase SHA-256 digest of the canonical contract.
func Digest(contract Contract) (string, error) {
	canonical, err := CanonicalBytes(contract)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
