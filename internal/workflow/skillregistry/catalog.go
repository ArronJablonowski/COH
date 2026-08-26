package skillregistry

import (
	"crypto/subtle"
	"slices"
)

type catalogDigestWire struct {
	SchemaVersion   string             `json:"schema_version"`
	ContractVersion string             `json:"contract_version"`
	OrganizationID  string             `json:"organization_id"`
	TenantID        string             `json:"tenant_id"`
	Entries         []PromotedSkillRef `json:"entries"`
	UpdatedAt       string             `json:"updated_at"`
	Revision        uint64             `json:"revision"`
}

func catalogSnapshotDigest(value CatalogSnapshot) (string, error) {
	canonical, err := canonicalValue(catalogDigestWire{SchemaVersion: value.SchemaVersion,
		ContractVersion: value.ContractVersion, OrganizationID: value.OrganizationID,
		TenantID: value.TenantID, Entries: append([]PromotedSkillRef(nil), value.Entries...),
		UpdatedAt: formatTime(value.UpdatedAt), Revision: value.Revision})
	if err != nil {
		return "", err
	}
	return digestBytes(canonical), nil
}

func validateCatalogSnapshot(value CatalogSnapshot) error {
	if value.SchemaVersion != CatalogSchemaVersion || value.ContractVersion != ContractVersion ||
		!validUUID(value.OrganizationID) || !validUUID(value.TenantID) || value.Entries == nil ||
		len(value.Entries) > MaximumCatalogEntries {
		return newError(Denied, "catalog_snapshot_invalid", false, nil)
	}
	if value.Revision == 0 {
		if len(value.Entries) != 0 || !value.UpdatedAt.IsZero() {
			return newError(Denied, "catalog_empty_snapshot_invalid", false, nil)
		}
	} else if !validTime(value.UpdatedAt) {
		return newError(Denied, "catalog_timestamp_invalid", false, nil)
	}
	for index, entry := range value.Entries {
		if !tokenPattern.MatchString(entry.SkillName) || !validDigest(entry.ManifestDigest) ||
			entry.StateRevision == 0 || !validDigest(entry.ProvenanceDigest) ||
			index > 0 && value.Entries[index-1].SkillName >= entry.SkillName {
			return newError(Denied, "catalog_entry_invalid", false, nil)
		}
	}
	expected, err := catalogSnapshotDigest(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(value.SnapshotDigest)) != 1 {
		return newError(Denied, "catalog_digest_invalid", false, err)
	}
	return nil
}

func cloneCatalogSnapshot(value CatalogSnapshot) CatalogSnapshot {
	value.Entries = slices.Clone(value.Entries)
	return value
}
