package evidenceingest

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

type transportWire struct {
	Mode                 TransportMode `json:"mode"`
	PeerIdentityDigest   string        `json:"peer_identity_digest"`
	ChannelBindingDigest string        `json:"channel_binding_digest"`
}

type observedTimeWire struct {
	Value                 string        `json:"value"`
	OriginalOffsetMinutes int16         `json:"original_offset_minutes"`
	Precision             TimePrecision `json:"precision"`
	UncertaintyNanos      uint64        `json:"uncertainty_nanos"`
}

type sourceRangeWire struct {
	Start observedTimeWire `json:"start"`
	End   observedTimeWire `json:"end"`
}

type sourceWire struct {
	Kind                    SourceKind        `json:"kind"`
	Identity                string            `json:"identity"`
	IdentityDigest          string            `json:"identity_digest"`
	CollectionMethod        string            `json:"collection_method"`
	CollectionMethodVersion string            `json:"collection_method_version"`
	CollectedAt             string            `json:"collected_at"`
	SourceTime              *observedTimeWire `json:"source_time"`
	SourceRange             *sourceRangeWire  `json:"source_range"`
}

type componentWire struct {
	Kind    ComponentKind `json:"kind"`
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Digest  string        `json:"digest"`
}

type commandWire struct {
	SchemaVersion         string          `json:"schema_version"`
	ContractVersion       string          `json:"contract_version"`
	RequestID             string          `json:"request_id"`
	IdempotencyKey        string          `json:"idempotency_key"`
	Case                  caseWire        `json:"case"`
	ActorID               string          `json:"actor_id"`
	ActorRevision         uint64          `json:"actor_revision"`
	ExpectedDigest        string          `json:"expected_digest"`
	ExpectedLength        int64           `json:"expected_length"`
	MediaType             string          `json:"media_type"`
	Classification        string          `json:"classification"`
	Source                sourceWire      `json:"source"`
	ParentArtifacts       []artifactWire  `json:"parent_artifacts"`
	ParentManifestDigests []string        `json:"parent_manifest_digests"`
	Components            []componentWire `json:"components"`
	KeyProfile            string          `json:"key_profile"`
	KeyProfileDigest      string          `json:"key_profile_digest"`
	PolicyDigest          string          `json:"policy_digest"`
	Transport             transportWire   `json:"transport"`
	Deadline              string          `json:"deadline"`
}

type authorizationWire struct {
	SchemaVersion        string      `json:"schema_version"`
	ContractVersion      string      `json:"contract_version"`
	AuthorizationDigest  string      `json:"authorization_digest"`
	IntentDigest         string      `json:"intent_digest"`
	Command              commandWire `json:"command"`
	CaseRevision         uint64      `json:"case_revision"`
	CaseState            string      `json:"case_state"`
	CaseClassification   string      `json:"case_classification"`
	CaseProvenanceDigest string      `json:"case_provenance_digest"`
}

type decisionWire struct {
	SchemaVersion       string   `json:"schema_version"`
	ContractVersion     string   `json:"contract_version"`
	DecisionID          string   `json:"decision_id"`
	DecisionDigest      string   `json:"decision_digest"`
	AuthorizationDigest string   `json:"authorization_digest"`
	IntentDigest        string   `json:"intent_digest"`
	Case                caseWire `json:"case"`
	ActorID             string   `json:"actor_id"`
	ActorRevision       uint64   `json:"actor_revision"`
	ArtifactDigest      string   `json:"artifact_digest"`
	ArtifactLength      int64    `json:"artifact_length"`
	PolicyDigest        string   `json:"policy_digest"`
	KeyProfileDigest    string   `json:"key_profile_digest"`
	TransportDigest     string   `json:"transport_digest"`
	RevocationDigest    string   `json:"revocation_digest"`
	Outcome             string   `json:"outcome"`
	ReasonCode          string   `json:"reason_code"`
	IssuedAt            string   `json:"issued_at"`
	ExpiresAt           string   `json:"expires_at"`
	Revision            uint64   `json:"revision"`
}

type manifestWire struct {
	SchemaVersion            string          `json:"schema_version"`
	ContractVersion          string          `json:"contract_version"`
	ManifestID               string          `json:"manifest_id"`
	Case                     caseWire        `json:"case"`
	Artifact                 artifactWire    `json:"artifact"`
	Source                   sourceWire      `json:"source"`
	ParentArtifacts          []artifactWire  `json:"parent_artifacts"`
	ParentManifestDigests    []string        `json:"parent_manifest_digests"`
	Components               []componentWire `json:"components"`
	ActorID                  string          `json:"actor_id"`
	ActorRevision            uint64          `json:"actor_revision"`
	PolicyDigest             string          `json:"policy_digest"`
	AuthorizationDigest      string          `json:"authorization_digest"`
	DecisionDigest           string          `json:"decision_digest"`
	RevocationDigest         string          `json:"revocation_digest"`
	TransportDigest          string          `json:"transport_digest"`
	EncryptionContextDigest  string          `json:"encryption_context_digest"`
	AuditEventDigest         string          `json:"audit_event_digest"`
	PreviousProvenanceDigest *string         `json:"previous_provenance_digest"`
	ProvenanceDigest         string          `json:"provenance_digest"`
	CreatedAt                string          `json:"created_at"`
	Revision                 uint64          `json:"revision"`
}

type encryptedObjectWire struct {
	SchemaVersion           string   `json:"schema_version"`
	ContractVersion         string   `json:"contract_version"`
	Status                  Status   `json:"status"`
	Case                    caseWire `json:"case"`
	PlaintextDigest         string   `json:"plaintext_digest"`
	PlaintextLength         int64    `json:"plaintext_length"`
	CiphertextDigest        string   `json:"ciphertext_digest"`
	CiphertextLength        int64    `json:"ciphertext_length"`
	MediaType               string   `json:"media_type"`
	Classification          string   `json:"classification"`
	EncryptionFormat        string   `json:"encryption_format"`
	ChunkSize               uint32   `json:"chunk_size"`
	ChunkCount              uint64   `json:"chunk_count"`
	KeyReference            string   `json:"key_reference"`
	KeyRevision             uint64   `json:"key_revision"`
	KeyAlgorithm            string   `json:"key_algorithm"`
	WrappedKeyDigest        string   `json:"wrapped_key_digest"`
	EncryptionContextDigest string   `json:"encryption_context_digest"`
	LocatorDigest           string   `json:"locator_digest"`
	CreatedAt               string   `json:"created_at"`
}

type publishedObjectWire struct {
	Case                    caseWire `json:"case"`
	PlaintextDigest         string   `json:"plaintext_digest"`
	PlaintextLength         int64    `json:"plaintext_length"`
	CiphertextDigest        string   `json:"ciphertext_digest"`
	CiphertextLength        int64    `json:"ciphertext_length"`
	EncryptionFormat        string   `json:"encryption_format"`
	EncryptionContextDigest string   `json:"encryption_context_digest"`
	LocatorDigest           string   `json:"locator_digest"`
}

type receiptWire struct {
	SchemaVersion            string              `json:"schema_version"`
	ContractVersion          string              `json:"contract_version"`
	RequestID                string              `json:"request_id"`
	Case                     caseWire            `json:"case"`
	ActorID                  string              `json:"actor_id"`
	ActorRevision            uint64              `json:"actor_revision"`
	IntentDigest             string              `json:"intent_digest"`
	IdempotencyDigest        string              `json:"idempotency_digest"`
	AuthorizationDigest      string              `json:"authorization_digest"`
	DecisionDigest           string              `json:"decision_digest"`
	RevocationDigest         string              `json:"revocation_digest"`
	TransportDigest          string              `json:"transport_digest"`
	Artifact                 artifactWire        `json:"artifact"`
	Manifest                 artifactWire        `json:"manifest"`
	EncryptedArtifact        publishedObjectWire `json:"encrypted_artifact"`
	EncryptedManifest        publishedObjectWire `json:"encrypted_manifest"`
	ManifestProvenanceDigest string              `json:"manifest_provenance_digest"`
	AuditEventDigest         string              `json:"audit_event_digest"`
	CreatedAt                string              `json:"created_at"`
	ReceiptDigest            string              `json:"receipt_digest"`
}
