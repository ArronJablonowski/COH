// Package normalizedevent defines the OCSF-first, ECS-preserving event
// envelope and its evidence and dataset verification boundaries.
package normalizedevent

import "encoding/json"

const (
	EnvelopeSchemaVersion = "coh.normalized-event-envelope/v1"
	ContractVersion       = "1.0.0"
	OCSFVersion           = "1.9.0"
	OCSFCommit            = "856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba"
	ECSVersion            = "9.5.0"
	ECSCommit             = "401807e0547301525acd28c4fb667203fec66d59"
	TargetManifestDigest  = "sha256:82b23c1229c4bb1dbdc047859614d8da924d5bd3e5bdf9efba62b31a397408c1"
	MaximumInputBytes     = 1 << 20
)

type Case struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type Source struct {
	Kind                    string `json:"kind"`
	Identity                string `json:"identity"`
	IdentityDigest          string `json:"identity_digest"`
	CollectionMethod        string `json:"collection_method"`
	CollectionMethodVersion string `json:"collection_method_version"`
}

type Artifact struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type Compatibility struct {
	TargetManifestDigest string `json:"target_manifest_digest"`
	OCSFVersion          string `json:"ocsf_version"`
	OCSFCommit           string `json:"ocsf_commit"`
	ECSVersion           string `json:"ecs_version"`
	ECSCommit            string `json:"ecs_commit"`
}

type Original struct {
	Format       string          `json:"format"`
	Fields       json.RawMessage `json:"fields"`
	FieldsDigest string          `json:"fields_digest"`
}

type OCSF struct {
	Version      string          `json:"version"`
	SchemaCommit string          `json:"schema_commit"`
	Event        json.RawMessage `json:"event"`
	EventDigest  string          `json:"event_digest"`
}

type ECS struct {
	Version      string          `json:"version"`
	SchemaCommit string          `json:"schema_commit"`
	Fields       json.RawMessage `json:"fields"`
	FieldsDigest string          `json:"fields_digest"`
}

type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type Normalization struct {
	MappingSetDigest     string    `json:"mapping_set_digest"`
	Normalizer           Component `json:"normalizer"`
	Coverage             string    `json:"coverage"`
	UnmappedVendorPaths  []string  `json:"unmapped_vendor_paths"`
	TransformationDigest string    `json:"transformation_digest"`
}

type Lineage struct {
	RawArtifact            Artifact `json:"raw_artifact"`
	RawManifestDigest      string   `json:"raw_manifest_digest"`
	IngestReceiptDigest    string   `json:"ingest_receipt_digest"`
	SourceProvenanceDigest string   `json:"source_provenance_digest"`
	ParentEnvelopeDigests  []string `json:"parent_envelope_digests"`
}

type AccessProfile struct {
	MaxRows       uint64 `json:"max_rows"`
	MaxBytes      uint64 `json:"max_bytes"`
	MaxPages      uint32 `json:"max_pages"`
	MaxDurationMS uint32 `json:"max_duration_ms"`
}

type Dataset struct {
	Format          string            `json:"format"`
	Artifact        Artifact          `json:"artifact"`
	ManifestDigest  string            `json:"manifest_digest"`
	SchemaDigest    string            `json:"schema_digest"`
	PartitionKeys   []string          `json:"partition_keys"`
	PartitionValues map[string]string `json:"partition_values"`
	RowGroup        uint32            `json:"row_group"`
	RowIndex        uint64            `json:"row_index"`
	AccessProfile   AccessProfile     `json:"access_profile"`
}

type Envelope struct {
	SchemaVersion   string        `json:"schema_version"`
	ContractVersion string        `json:"contract_version"`
	EnvelopeID      string        `json:"envelope_id"`
	Case            Case          `json:"case"`
	Source          Source        `json:"source"`
	Classification  string        `json:"classification"`
	CollectedAt     string        `json:"collected_at"`
	Compatibility   Compatibility `json:"compatibility"`
	Original        Original      `json:"original"`
	OCSF            OCSF          `json:"ocsf"`
	ECS             *ECS          `json:"ecs"`
	Normalization   Normalization `json:"normalization"`
	Lineage         Lineage       `json:"lineage"`
	Dataset         *Dataset      `json:"dataset"`
}

type ValidatedEnvelope struct {
	digest string
	value  Envelope
	bytes  []byte
}

func (validated ValidatedEnvelope) Digest() string { return validated.digest }

func (validated ValidatedEnvelope) CanonicalBytes() []byte {
	return append([]byte(nil), validated.bytes...)
}

func (validated ValidatedEnvelope) Value() Envelope {
	return cloneEnvelope(validated.value)
}

func cloneEnvelope(value Envelope) Envelope {
	encoded, _ := json.Marshal(value)
	var clone Envelope
	_ = json.Unmarshal(encoded, &clone)
	return clone
}
