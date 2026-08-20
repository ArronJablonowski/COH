package supplychain

const (
	SignatureSchema = "coh.release-signature/v1"
	ManifestSchema  = "coh.release-manifest/v1"
	ContractVersion = "1.0.0"
	MaximumFileSize = 256 << 20
)

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
}

// Signature is a detached signature over a domain-separated canonical subject.
type Signature struct {
	SchemaVersion string   `json:"schema_version"`
	Algorithm     string   `json:"algorithm"`
	KeyID         string   `json:"key_id"`
	Role          string   `json:"role"`
	Issue         string   `json:"issue"`
	Requirements  []string `json:"requirements"`
	Subject       Artifact `json:"subject"`
	Value         string   `json:"signature"`
}

type Manifest struct {
	SchemaVersion  string     `json:"schema_version"`
	Version        string     `json:"version"`
	Issue          string     `json:"issue"`
	Requirements   []string   `json:"requirements"`
	ReleaseVersion string     `json:"release_version"`
	Target         string     `json:"target"`
	Artifacts      []Artifact `json:"artifacts"`
	ManifestDigest string     `json:"manifest_digest"`
}

type TrustedKey struct {
	KeyID     string
	Role      string
	PublicPEM []byte
}

type ArchiveRequirement struct {
	Path    string `json:"path"`
	Mode    int64  `json:"mode"`
	Package string `json:"package,omitempty"`
}
