package filesize

const (
	PolicySchema        = "coh.file-size-policy/v1"
	ReportSchema        = "coh.file-size-report/v1"
	PolicyVersion       = "1.0.0"
	ReportVersion       = "1.0.0"
	MaximumPolicySize   = 1 << 20
	MaximumInputSize    = 8 << 20
	MaximumFileCount    = 100_000
	MaximumPathSize     = 4096
	MaximumIdentitySize = 256
	MaximumExceptions   = 256
	MaximumApproved     = 1_000_000
	WarningLimit        = 500
	HardLimit           = 800
	ScriptLimit         = 300
	NormalMinimum       = 150
	NormalMaximum       = 400
)

type Thresholds struct {
	WarningPhysicalLines int `json:"warning_physical_lines"`
	HardPhysicalLines    int `json:"hard_physical_lines"`
	ScriptPhysicalLines  int `json:"script_physical_lines"`
	NormalMinimumLines   int `json:"normal_minimum_lines"`
	NormalMaximumLines   int `json:"normal_maximum_lines"`
}

type Exception struct {
	Path                     string `json:"path"`
	Category                 string `json:"category"`
	Owner                    string `json:"owner"`
	Justification            string `json:"justification"`
	ExpiresOn                string `json:"expires_on"`
	TrackingIssue            string `json:"tracking_issue"`
	ContentSHA256            string `json:"content_sha256"`
	ApprovedMaxPhysicalLines int    `json:"approved_max_physical_lines"`
	Generator                string `json:"generator,omitempty"`
}

type Policy struct {
	SchemaVersion string      `json:"schema_version"`
	PolicyVersion string      `json:"policy_version"`
	Thresholds    Thresholds  `json:"thresholds"`
	Exceptions    []Exception `json:"exceptions"`
}

type Finding struct {
	Path          string `json:"path"`
	Class         string `json:"class"`
	PhysicalLines int    `json:"physical_lines"`
	Limit         int    `json:"limit"`
	Reason        string `json:"reason"`
	TrackingIssue string `json:"tracking_issue,omitempty"`
}

type Counts struct {
	Checked    int `json:"checked"`
	Skipped    int `json:"skipped"`
	Warnings   int `json:"warnings"`
	Denials    int `json:"denials"`
	Exceptions int `json:"exceptions"`
}

type Report struct {
	SchemaVersion    string     `json:"schema_version"`
	ReportVersion    string     `json:"report_version"`
	Issue            string     `json:"issue"`
	Requirements     []string   `json:"requirements"`
	Outcome          string     `json:"outcome"`
	FailureCode      ErrorCode  `json:"failure_code,omitempty"`
	PolicyDigest     string     `json:"policy_digest"`
	ExceptionsDigest string     `json:"exceptions_digest"`
	SourceDigest     string     `json:"source_digest"`
	SourceFileCount  int        `json:"source_file_count"`
	VCSRevision      string     `json:"vcs_revision"`
	VCSModified      bool       `json:"vcs_modified"`
	EvaluationDate   string     `json:"evaluation_date"`
	Thresholds       Thresholds `json:"thresholds"`
	Counts           Counts     `json:"counts"`
	ScanComplete     bool       `json:"scan_complete"`
	Findings         []Finding  `json:"findings"`
	ReportDigest     string     `json:"report_digest"`
}

type FileRecord struct {
	Path       string `json:"path"`
	Length     int64  `json:"length"`
	Executable bool   `json:"executable"`
	SHA256     string `json:"sha256"`
	Mode       uint32 `json:"-"`
	Identity   string `json:"-"`
}

type Snapshot struct {
	Digest      string
	FileCount   int
	VCSRevision string
	VCSModified bool
	Records     []FileRecord
}
