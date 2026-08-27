package evidenceingest

import "github.com/ArronJablonowski/COH/internal/domain"

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func artifactFromWire(value artifactWire) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func publishedObjectFromWire(value publishedObjectWire) PublishedObject {
	return PublishedObject{Case: caseFromWire(value.Case), PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, CiphertextDigest: value.CiphertextDigest,
		CiphertextLength: value.CiphertextLength, EncryptionFormat: value.EncryptionFormat,
		EncryptionContextDigest: value.EncryptionContextDigest, LocatorDigest: value.LocatorDigest}
}

func receiptFromWire(value receiptWire) (Receipt, error) {
	createdAt, err := parseTime(value.CreatedAt)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, Case: caseFromWire(value.Case), ActorID: value.ActorID,
		ActorRevision: value.ActorRevision, IntentDigest: value.IntentDigest,
		IdempotencyDigest: value.IdempotencyDigest, AuthorizationDigest: value.AuthorizationDigest,
		DecisionDigest: value.DecisionDigest, RevocationDigest: value.RevocationDigest,
		TransportDigest: value.TransportDigest, Artifact: artifactFromWire(value.Artifact),
		Manifest: artifactFromWire(value.Manifest), EncryptedArtifact: publishedObjectFromWire(value.EncryptedArtifact),
		EncryptedManifest:        publishedObjectFromWire(value.EncryptedManifest),
		ManifestProvenanceDigest: value.ManifestProvenanceDigest, AuditEventDigest: value.AuditEventDigest,
		CreatedAt: createdAt, ReceiptDigest: value.ReceiptDigest}, nil
}
