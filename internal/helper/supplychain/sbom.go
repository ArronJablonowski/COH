package supplychain

import (
	"encoding/json"
	"slices"
	"strings"
)

type ReleaseSBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     SBOMMetadata    `json:"metadata"`
	Components   []SBOMComponent `json:"components"`
}

type SBOMMetadata struct {
	Component SBOMComponent `json:"component"`
}

type SBOMComponent struct {
	Type     string              `json:"type"`
	BOMRef   string              `json:"bom-ref"`
	Name     string              `json:"name"`
	Version  string              `json:"version"`
	Hashes   []SBOMHash          `json:"hashes"`
	Licenses []SBOMLicenseChoice `json:"licenses"`
}

type SBOMHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

type SBOMLicenseChoice struct {
	License SBOMLicense `json:"license"`
}

type SBOMLicense struct {
	ID string `json:"id"`
}

func GenerateReleaseSBOM(archive Artifact, entries []ArchiveEntry, version, target string) ([]byte, error) {
	if filepathBaseInvalid(archive.Path) || !validDigest(archive.SHA256) || archive.Length < 1 ||
		!validVersion(version) || !validTarget(target) || len(entries) == 0 {
		return nil, errorf(CodeInvalidInput, "sbom", "release subject or identity is invalid", nil)
	}
	root := SBOMComponent{
		Type: "application", BOMRef: releasePURL(version, target),
		Name: "COH", Version: version, Hashes: []SBOMHash{{Algorithm: "SHA-256", Content: archive.SHA256}},
		Licenses: []SBOMLicenseChoice{{License: SBOMLicense{ID: "Apache-2.0"}}},
	}
	components := make([]SBOMComponent, 0, len(entries))
	for _, entry := range entries {
		if !validArchivePath(entry.Path) || !validDigest(entry.SHA256) || entry.Length < 0 {
			return nil, errorf(CodeInvalidInput, "sbom.components", "archive entry is invalid", nil)
		}
		components = append(components, SBOMComponent{
			Type: "file", BOMRef: "file:" + entry.Path, Name: entry.Path, Version: version,
			Hashes:   []SBOMHash{{Algorithm: "SHA-256", Content: entry.SHA256}},
			Licenses: []SBOMLicenseChoice{{License: SBOMLicense{ID: "Apache-2.0"}}},
		})
	}
	slices.SortFunc(components, func(a, b SBOMComponent) int { return strings.Compare(a.BOMRef, b.BOMRef) })
	identity, err := json.Marshal(struct {
		Root       SBOMComponent
		Components []SBOMComponent
	}{root, components})
	if err != nil {
		return nil, errorf(CodeToolFailure, "sbom", "cannot canonicalize SBOM identity", err)
	}
	bom := ReleaseSBOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", SerialNumber: deterministicUUID(identity),
		Version: 1, Metadata: SBOMMetadata{Component: root}, Components: components,
	}
	encoded, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, errorf(CodeToolFailure, "sbom", "cannot encode SBOM", err)
	}
	return append(encoded, '\n'), nil
}

func releasePURL(version, target string) string {
	parts := strings.Split(target, "/")
	return "pkg:generic/coh@" + version + "?arch=" + parts[1] + "&os=" + parts[0]
}

func VerifyReleaseSBOM(encoded []byte, archive Artifact, entries []ArchiveEntry, version, target string) error {
	expected, err := GenerateReleaseSBOM(archive, entries, version, target)
	if err != nil {
		return err
	}
	var actual ReleaseSBOM
	if err := decodeStrict(encoded, &actual); err != nil {
		return errorf(CodeInvalidInput, "sbom", "invalid CycloneDX document", err)
	}
	var wanted ReleaseSBOM
	if err := decodeStrict(expected, &wanted); err != nil {
		return errorf(CodeToolFailure, "sbom", "cannot decode generated SBOM", err)
	}
	if !slices.Equal(encoded, expected) || actual.SerialNumber != wanted.SerialNumber {
		return errorf(CodeDenied, "sbom", "SBOM differs from canonical release inventory", nil)
	}
	return nil
}

func filepathBaseInvalid(value string) bool {
	return value == "" || strings.ContainsAny(value, "/\\")
}
