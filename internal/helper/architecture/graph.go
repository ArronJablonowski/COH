package architecture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Evaluate checks production and test imports against the contract. It is pure
// apart from observing context cancellation, so a denied or interrupted run
// can be safely repeated without recovery state.
func Evaluate(ctx context.Context, contract Contract, packages []Package, provenance Provenance) (Report, error) {
	report, err := NewReport(contract, provenance)
	if err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		report.Outcome = "canceled"
		report.FailureCode = CodeCanceled
		return report, contractError(CodeCanceled, "$", "evaluation canceled", err)
	}
	report.GraphDigest, err = digestGraph(packages)
	if err != nil {
		report.Outcome = "error"
		report.FailureCode = CodeInvalidInput
		return report, err
	}

	allowed := allowedImports(contract)
	seenPackages := make(map[string]struct{}, len(packages))
	for index, pkg := range packages {
		if err := ctx.Err(); err != nil {
			report.Outcome = "canceled"
			report.FailureCode = CodeCanceled
			return report, contractError(CodeCanceled, fmt.Sprintf("packages[%d]", index), "evaluation canceled", err)
		}
		if !isLocal(contract.Module, pkg.ImportPath) {
			continue
		}
		if _, duplicate := seenPackages[pkg.ImportPath]; duplicate {
			report.Outcome = "error"
			report.FailureCode = CodeInvalidInput
			return report, contractError(CodeInvalidInput, fmt.Sprintf("packages[%d].ImportPath", index), "duplicate package", nil)
		}
		seenPackages[pkg.ImportPath] = struct{}{}
		report.PackageCount++
		source := classify(contract, pkg.ImportPath)
		if source == "" {
			report.Violations = append(report.Violations, Violation{
				Rule: "ARCH-001", Package: pkg.ImportPath, Boundary: "unclassified",
				Detail: "every local Go package must belong to a declared boundary",
			})
			continue
		}

		imports := uniqueImports(pkg)
		for _, imported := range imports {
			if !isLocal(contract.Module, imported) {
				continue
			}
			target := classify(contract, imported)
			if target == "" {
				report.Violations = append(report.Violations, Violation{
					Rule: "ARCH-001", Package: pkg.ImportPath, Boundary: source,
					Import: imported, ImportBoundary: "unclassified",
					Detail: "local import is outside all declared boundaries",
				})
				continue
			}
			if isProtectedCompositionImport(contract.Module, imported) && source != "command" && source != "broker" {
				report.Violations = append(report.Violations, Violation{
					Rule: "ARCH-003", Package: pkg.ImportPath, Boundary: source,
					Import: imported, ImportBoundary: target,
					Detail: "capability composition authority is restricted to command and broker roots",
				})
				continue
			}
			if isProtectedProfileCompositionImport(contract.Module, imported) && source != "command" {
				report.Violations = append(report.Violations, Violation{
					Rule: "ARCH-004", Package: pkg.ImportPath, Boundary: source,
					Import: imported, ImportBoundary: target,
					Detail: "profile composition is restricted to the command root",
				})
				continue
			}
			if _, ok := allowed[source][target]; !ok {
				report.Violations = append(report.Violations, Violation{
					Rule: "ARCH-002", Package: pkg.ImportPath, Boundary: source,
					Import: imported, ImportBoundary: target,
					Detail: "reverse or cross-adapter dependency is forbidden",
				})
			}
		}
	}

	slices.SortFunc(report.Violations, func(a, b Violation) int {
		left := a.Package + "\x00" + a.Import + "\x00" + a.Rule
		right := b.Package + "\x00" + b.Import + "\x00" + b.Rule
		return strings.Compare(left, right)
	})
	report.ViolationCount = len(report.Violations)
	if report.ViolationCount > 0 {
		report.Outcome = "denied"
		report.FailureCode = CodeDenied
		return report, contractError(CodeDenied, "imports", fmt.Sprintf("%d dependency violation(s)", report.ViolationCount), nil)
	}
	return report, nil
}

func isProtectedCompositionImport(module, imported string) bool {
	root := module + "/internal/domain/capabilityseam"
	return imported == root || strings.HasPrefix(imported, root+"/")
}

func isProtectedProfileCompositionImport(module, imported string) bool {
	root := module + "/internal/domain/profilecomposition"
	return imported == root || strings.HasPrefix(imported, root+"/")
}

// NewReport creates provenance-bearing evidence even when discovery is later
// canceled or fails. No package or source content is embedded.
func NewReport(contract Contract, provenance Provenance) (Report, error) {
	if err := ValidateContract(contract); err != nil {
		return Report{}, err
	}
	digest, err := Digest(contract)
	if err != nil {
		return Report{}, err
	}
	if provenance.BuildTags == nil {
		provenance.BuildTags = []string{}
	}
	return Report{
		SchemaVersion: contract.SchemaVersion, ContractVersion: contract.ContractVersion,
		ContractDigest: digest, Module: contract.Module, Outcome: "allowed",
		Provenance: provenance, Violations: []Violation{},
	}, nil
}

type graphEntry struct {
	Package string   `json:"package"`
	Imports []string `json:"imports"`
}

func digestGraph(packages []Package) (string, error) {
	entries := make([]graphEntry, 0, len(packages))
	for index, pkg := range packages {
		if pkg.ImportPath == "" {
			return "", contractError(CodeInvalidInput, fmt.Sprintf("packages[%d].ImportPath", index), "import path is required", nil)
		}
		entries = append(entries, graphEntry{Package: pkg.ImportPath, Imports: uniqueImports(pkg)})
	}
	slices.SortFunc(entries, func(a, b graphEntry) int { return strings.Compare(a.Package, b.Package) })
	canonical, err := json.Marshal(entries)
	if err != nil {
		return "", contractError(CodeInvalidInput, "packages", "cannot encode import graph", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func allowedImports(contract Contract) map[string]map[string]struct{} {
	allowed := make(map[string]map[string]struct{}, len(contract.Boundaries))
	for _, boundary := range contract.Boundaries {
		allowed[boundary.Name] = make(map[string]struct{}, len(boundary.MayImport))
		for _, imported := range boundary.MayImport {
			allowed[boundary.Name][imported] = struct{}{}
		}
	}
	return allowed
}

func uniqueImports(pkg Package) []string {
	seen := make(map[string]struct{}, len(pkg.Imports)+len(pkg.TestImports)+len(pkg.XTestImports))
	for _, imported := range append(append(slices.Clone(pkg.Imports), pkg.TestImports...), pkg.XTestImports...) {
		seen[imported] = struct{}{}
	}
	imports := make([]string, 0, len(seen))
	for imported := range seen {
		imports = append(imports, imported)
	}
	slices.Sort(imports)
	return imports
}

func isLocal(module, importPath string) bool {
	return importPath == module || strings.HasPrefix(importPath, module+"/")
}

func classify(contract Contract, importPath string) string {
	relative := strings.TrimPrefix(importPath, contract.Module)
	relative = strings.TrimPrefix(relative, "/")
	bestName, bestLength := "", -1
	for _, boundary := range contract.Boundaries {
		for _, root := range boundary.Roots {
			if (relative == root || strings.HasPrefix(relative, root+"/")) && len(root) > bestLength {
				bestName, bestLength = boundary.Name, len(root)
			}
		}
	}
	return bestName
}
