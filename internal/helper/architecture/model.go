// Package architecture validates the versioned Go workspace contract and
// evaluates local imports. It belongs to the dependency-free helper boundary.
package architecture

// These values are compatibility gates, not descriptive metadata. Changing
// them requires a reviewed contract-version change and fixture update.
const (
	SchemaVersion       = "coh.architecture/v1"
	Canonicalization    = "COH-JSON-C14N-1"
	SupportedMajor      = 1
	SupportedMinor      = 0
	BaselineGoVersion   = "1.26.7"
	ModulePath          = "github.com/ArronJablonowski/COH"
	CheckerVersion      = "0.1.0"
	MaximumContractSize = 1 << 20
)

// Contract is the executable package-boundary policy.
type Contract struct {
	SchemaVersion    string     `json:"schema_version"`
	ContractVersion  string     `json:"contract_version"`
	Canonicalization string     `json:"canonicalization"`
	GoBaseline       string     `json:"go_baseline"`
	Module           string     `json:"module"`
	Boundaries       []Boundary `json:"boundaries"`
}

// Boundary defines source roots and the only COH boundaries they may import.
type Boundary struct {
	Name      string   `json:"name"`
	Roots     []string `json:"roots"`
	Purpose   string   `json:"purpose"`
	MayImport []string `json:"may_import"`
}

// Package is the stable subset of `go list -json` used by the evaluator.
type Package struct {
	ImportPath   string       `json:"ImportPath"`
	Imports      []string     `json:"Imports"`
	TestImports  []string     `json:"TestImports"`
	XTestImports []string     `json:"XTestImports"`
	SourceFiles  []SourceFile `json:"-"`
}

// SourceFile binds parsed imports to the exact bytes used for provenance.
type SourceFile struct {
	Path   string `json:"path"`
	Length int    `json:"length"`
	Digest string `json:"sha256"`
}

// Provenance binds a verdict to source, revision, toolchain, and target inputs.
type Provenance struct {
	SourceDigest    string   `json:"source_digest"`
	SourceFileCount int      `json:"source_file_count"`
	InputDigest     string   `json:"input_digest"`
	InputFileCount  int      `json:"input_file_count"`
	VCSRevision     string   `json:"vcs_revision"`
	VCSModified     bool     `json:"vcs_modified"`
	CheckerVersion  string   `json:"checker_version"`
	GoVersion       string   `json:"go_version"`
	GOOS            string   `json:"goos"`
	GOARCH          string   `json:"goarch"`
	BuildTags       []string `json:"build_tags"`
}

// Violation describes one forbidden or unclassified local dependency.
type Violation struct {
	Rule           string `json:"rule"`
	Package        string `json:"package"`
	Boundary       string `json:"boundary"`
	Import         string `json:"import,omitempty"`
	ImportBoundary string `json:"import_boundary,omitempty"`
	Detail         string `json:"detail"`
}

// Report is deterministic evidence from one graph evaluation.
type Report struct {
	SchemaVersion   string      `json:"schema_version"`
	ContractVersion string      `json:"contract_version"`
	ContractDigest  string      `json:"contract_digest"`
	GraphDigest     string      `json:"graph_digest"`
	Module          string      `json:"module"`
	Outcome         string      `json:"outcome"`
	FailureCode     ErrorCode   `json:"failure_code,omitempty"`
	Provenance      Provenance  `json:"provenance"`
	PackageCount    int         `json:"package_count"`
	ViolationCount  int         `json:"violation_count"`
	Violations      []Violation `json:"violations"`
}
