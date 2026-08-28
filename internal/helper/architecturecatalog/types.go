// Package architecturecatalog generates publication-safe architecture evidence.
package architecturecatalog

const (
	SchemaVersion   = "coh.architecture-catalog/v1"
	ContractVersion = "1.0.0"
	MaximumBytes    = 8 << 20
)

var requirements = []string{"COH-E25-05", "EVAL-004", "EVAL-029", "NFR-019", "NFR-026"}

type Source struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
}

type Declaration struct {
	CatalogType string   `json:"catalog_type"`
	Sources     []Source `json:"sources"`
}

type Declarations struct {
	SchemaVersion   string        `json:"schema_version"`
	ContractVersion string        `json:"contract_version"`
	Catalogs        []Declaration `json:"catalogs"`
}

type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Record struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	Attributes []Attribute `json:"attributes"`
}

type Catalog struct {
	SchemaVersion   string   `json:"schema_version"`
	ContractVersion string   `json:"contract_version"`
	CatalogType     string   `json:"catalog_type"`
	Requirements    []string `json:"requirements"`
	Sources         []Source `json:"sources"`
	Records         []Record `json:"records"`
	CatalogDigest   string   `json:"catalog_digest"`
}

type goPackage struct {
	ImportPath   string   `json:"ImportPath"`
	Name         string   `json:"Name"`
	Dir          string   `json:"Dir"`
	Imports      []string `json:"Imports"`
	GoFiles      []string `json:"GoFiles"`
	CgoFiles     []string `json:"CgoFiles"`
	TestGoFiles  []string `json:"TestGoFiles"`
	XTestGoFiles []string `json:"XTestGoFiles"`
}
