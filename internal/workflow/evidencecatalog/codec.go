package evidencecatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

type caseWire struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type artifactWire struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type evidenceWire struct {
	Artifact                 artifactWire `json:"artifact"`
	Manifest                 artifactWire `json:"manifest"`
	ManifestProvenanceDigest string       `json:"manifest_provenance_digest"`
	IngestionReceiptDigest   string       `json:"ingestion_receipt_digest"`
}

type manifestArtifactWire struct {
	Ordinal                uint16       `json:"ordinal"`
	Role                   string       `json:"role"`
	Reference              evidenceWire `json:"reference"`
	ParentArtifactDigests  []string     `json:"parent_artifact_digests"`
	ParentManifestDigests  []string     `json:"parent_manifest_digests"`
	RedactionReceiptDigest *string      `json:"redaction_receipt_digest"`
	MappingDigest          *string      `json:"mapping_digest"`
}

type componentWire struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type recordWire struct {
	SchemaVersion      string                 `json:"schema_version"`
	ContractVersion    string                 `json:"contract_version"`
	Case               caseWire               `json:"case"`
	Artifacts          []manifestArtifactWire `json:"artifacts"`
	Components         []componentWire        `json:"components"`
	ArtifactSetDigest  string                 `json:"artifact_set_digest"`
	LineageDigest      string                 `json:"lineage_digest"`
	ComponentSetDigest string                 `json:"component_set_digest"`
}

type repositoryEnvelope struct {
	Schema         string          `json:"schema"`
	Kind           string          `json:"kind"`
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	TenantID       string          `json:"tenant_id"`
	CaseID         string          `json:"case_id"`
	Revision       uint64          `json:"revision"`
	EntryType      string          `json:"entry_type"`
	Data           json.RawMessage `json:"data"`
}

func recordToWire(value evidencelifecycle.VerifiedEvidenceSet) recordWire {
	artifacts := make([]manifestArtifactWire, len(value.Artifacts))
	for index, entry := range value.Artifacts {
		artifacts[index] = manifestArtifactWire{Ordinal: entry.Ordinal, Role: string(entry.Role),
			Reference:              evidenceToWire(entry.Reference),
			ParentArtifactDigests:  append([]string(nil), entry.ParentArtifactDigests...),
			ParentManifestDigests:  append([]string(nil), entry.ParentManifestDigests...),
			RedactionReceiptDigest: clonePointer(entry.RedactionReceiptDigest),
			MappingDigest:          clonePointer(entry.MappingDigest)}
	}
	components := make([]componentWire, len(value.Components))
	for index, component := range value.Components {
		components[index] = componentWire(component)
	}
	return recordWire{SchemaVersion: recordSchema, ContractVersion: recordContract, Case: caseToWire(value.Case),
		Artifacts: artifacts, Components: components, ArtifactSetDigest: value.ArtifactSetDigest,
		LineageDigest: value.LineageDigest, ComponentSetDigest: value.ComponentSetDigest}
}

func recordFromWire(value recordWire) evidencelifecycle.VerifiedEvidenceSet {
	artifacts := make([]evidencelifecycle.ManifestArtifact, len(value.Artifacts))
	for index, entry := range value.Artifacts {
		artifacts[index] = evidencelifecycle.ManifestArtifact{Ordinal: entry.Ordinal,
			Role: evidencelifecycle.ArtifactRole(entry.Role), Reference: evidenceFromWire(entry.Reference),
			ParentArtifactDigests:  append([]string(nil), entry.ParentArtifactDigests...),
			ParentManifestDigests:  append([]string(nil), entry.ParentManifestDigests...),
			RedactionReceiptDigest: clonePointer(entry.RedactionReceiptDigest),
			MappingDigest:          clonePointer(entry.MappingDigest)}
	}
	components := make([]evidencelifecycle.Component, len(value.Components))
	for index, component := range value.Components {
		components[index] = evidencelifecycle.Component(component)
	}
	return evidencelifecycle.VerifiedEvidenceSet{Case: caseFromWire(value.Case), Artifacts: artifacts,
		Components: components, ArtifactSetDigest: value.ArtifactSetDigest, LineageDigest: value.LineageDigest,
		ComponentSetDigest: value.ComponentSetDigest}
}

func evidenceToWire(value evidencelifecycle.EvidenceReference) evidenceWire {
	return evidenceWire{Artifact: artifactToWire(value.Artifact), Manifest: artifactToWire(value.Manifest),
		ManifestProvenanceDigest: value.ManifestProvenanceDigest,
		IngestionReceiptDigest:   value.IngestionReceiptDigest}
}

func evidenceFromWire(value evidenceWire) evidencelifecycle.EvidenceReference {
	return evidencelifecycle.EvidenceReference{Artifact: artifactFromWire(value.Artifact),
		Manifest: artifactFromWire(value.Manifest), ManifestProvenanceDigest: value.ManifestProvenanceDigest,
		IngestionReceiptDigest: value.IngestionReceiptDigest}
}

func artifactToWire(value domain.ArtifactRef) artifactWire {
	return artifactWire{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func artifactFromWire(value artifactWire) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func encode(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, lifecycleError(evidencelifecycle.InvalidInput, "catalog_encoding_invalid", false)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, lifecycleError(evidencelifecycle.InvalidInput, "catalog_encoding_invalid", false)
	}
	return canonical, nil
}

func decode(data []byte, output any) error {
	if len(data) == 0 || len(data) > 16<<20 || !json.Valid(data) {
		return lifecycleError(evidencelifecycle.Denied, "catalog_encoding_invalid", false)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return lifecycleError(evidencelifecycle.Denied, "catalog_encoding_invalid", false)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return lifecycleError(evidencelifecycle.Denied, "catalog_encoding_invalid", false)
	}
	canonical, err := encode(output)
	if err != nil || !bytes.Equal(canonical, data) {
		return lifecycleError(evidencelifecycle.Denied, "catalog_noncanonical", false)
	}
	return nil
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func deterministicUUID(domainName, value string) string {
	sum := sha256.Sum256([]byte(domainName + value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func recordKey(scope domain.CaseRef, digest string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-ARTIFACT-SET-ID-V1\x00",
			scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID+"\x00"+digest)}
}
