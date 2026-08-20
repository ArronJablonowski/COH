package quality

const (
	PolicySchema      = "coh.ci-quality/v1"
	ReportSchema      = "coh.ci-quality-report/v1"
	ReportVersion     = "1.0.0"
	EvidenceSchema    = "coh.ci-evidence-manifest/v1"
	FailureSchema     = "coh.ci-failure-manifest/v1"
	PublicationSchema = "coh.ci-publication-manifest/v1"
	MaximumPolicySize = 1 << 20
)

// Policy selects a locked lane and the complete fixed stage set.
type Policy struct {
	SchemaVersion string      `json:"schema_version"`
	PolicyVersion string      `json:"policy_version"`
	Lanes         []Lane      `json:"lanes"`
	Stages        []StageSpec `json:"stages"`
}

type Lane struct {
	ID          string `json:"id"`
	GoVersion   string `json:"go_version"`
	Enforcement string `json:"enforcement"`
}

type StageSpec struct {
	ID             string `json:"id"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// Provenance binds a report to the reviewed policy, source set, tool lock,
// compiler, target, and VCS state without storing source or secrets.
type Provenance struct {
	PolicyDigest   string `json:"policy_digest"`
	ToolLockDigest string `json:"tool_lock_digest"`
	SourceDigest   string `json:"source_digest"`
	SourceFiles    int    `json:"source_file_count"`
	VCSRevision    string `json:"vcs_revision"`
	VCSModified    bool   `json:"vcs_modified"`
	GoVersion      string `json:"go_version"`
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
}

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
}

// EvidenceManifest is the final, deterministic inventory. It lists every
// regular artifact except itself, including the report and provenance.
type EvidenceManifest struct {
	SchemaVersion  string     `json:"schema_version"`
	Issue          string     `json:"issue"`
	Requirements   []string   `json:"requirements"`
	Artifacts      []Artifact `json:"artifacts"`
	ManifestDigest string     `json:"manifest_digest"`
}

type PublicationManifest struct {
	SchemaVersion         string     `json:"schema_version"`
	Issue                 string     `json:"issue"`
	Requirements          []string   `json:"requirements"`
	QualityGatePromotable bool       `json:"quality_gate_promotable"`
	Artifacts             []Artifact `json:"artifacts"`
	ManifestDigest        string     `json:"manifest_digest"`
}

type FailureManifest struct {
	SchemaVersion  string     `json:"schema_version"`
	Issue          string     `json:"issue"`
	Requirements   []string   `json:"requirements"`
	Outcome        string     `json:"outcome"`
	FailureCode    ErrorCode  `json:"failure_code"`
	Artifacts      []Artifact `json:"artifacts"`
	ManifestDigest string     `json:"manifest_digest"`
}

type FailureEvidence struct {
	Expected string    `json:"expected"`
	Status   string    `json:"status"`
	ExitCode int       `json:"exit_code"`
	Artifact *Artifact `json:"artifact,omitempty"`
}

type VerificationResult struct {
	Outcome     string    `json:"outcome"`
	FailureCode ErrorCode `json:"failure_code,omitempty"`
}

type StageResult struct {
	ID              string           `json:"id"`
	Outcome         string           `json:"outcome"`
	FailureCode     ErrorCode        `json:"failure_code,omitempty"`
	CommandDigest   string           `json:"command_digest"`
	Evidence        []string         `json:"evidence,omitempty"`
	FailureEvidence *FailureEvidence `json:"failure_evidence,omitempty"`
	Note            string           `json:"note,omitempty"`
}

// Report is deterministic for a fixed tree, policy, lane, and outcomes. It
// intentionally omits wall-clock timestamps and durations.
type Report struct {
	SchemaVersion         string              `json:"schema_version"`
	ReportVersion         string              `json:"report_version"`
	Issue                 string              `json:"issue"`
	Requirements          []string            `json:"requirements"`
	Outcome               string              `json:"outcome"`
	FailureCode           ErrorCode           `json:"failure_code,omitempty"`
	Lane                  Lane                `json:"lane"`
	QualityGatePromotable bool                `json:"quality_gate_promotable"`
	Provenance            Provenance          `json:"provenance"`
	Stages                []StageResult       `json:"stages"`
	Verification          *VerificationResult `json:"verification"`
	ReportDigest          string              `json:"report_digest"`
}

type ToolLock struct {
	SchemaVersion string           `json:"schema_version"`
	Tools         []ToolSpec       `json:"tools"`
	BinaryTools   []BinaryToolSpec `json:"binary_tools"`
}

type BinaryToolSpec struct {
	ID        string              `json:"id"`
	Command   string              `json:"command"`
	Version   string              `json:"version"`
	License   string              `json:"license"`
	Platforms []BinaryPlatformPin `json:"platforms"`
}

type BinaryPlatformPin struct {
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	Asset         string `json:"asset"`
	ArchiveSHA256 string `json:"archive_sha256"`
	BinarySHA256  string `json:"binary_sha256"`
}

type ToolSpec struct {
	ID         string          `json:"id"`
	Command    string          `json:"command"`
	Package    string          `json:"package"`
	Module     string          `json:"module"`
	Version    string          `json:"version"`
	ModuleSum  string          `json:"module_sum"`
	GoModSum   string          `json:"go_mod_sum"`
	OriginHash string          `json:"origin_hash"`
	Binaries   []ToolBinaryPin `json:"binaries"`
}

type ToolBinaryPin struct {
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	SHA256    string `json:"sha256"`
}

type Snapshot struct {
	Digest      string
	FileCount   int
	VCSRevision string
	VCSModified bool
	records     []fileRecord
}

type fileRecord struct {
	Path   string `json:"path"`
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}
