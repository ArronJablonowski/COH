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

func observedTimeFromWire(value observedTimeWire) (ObservedTime, error) {
	parsed, err := parseTime(value.Value)
	if err != nil {
		return ObservedTime{}, err
	}
	return ObservedTime{Value: parsed, OriginalOffsetMinutes: value.OriginalOffsetMinutes,
		Precision: value.Precision, UncertaintyNanos: value.UncertaintyNanos}, nil
}

func sourceFromWire(value sourceWire) (SourceInput, error) {
	collectedAt, err := parseTime(value.CollectedAt)
	if err != nil {
		return SourceInput{}, err
	}
	result := SourceInput{Kind: value.Kind, Identity: value.Identity, IdentityDigest: value.IdentityDigest,
		CollectionMethod: value.CollectionMethod, CollectionMethodVersion: value.CollectionMethodVersion,
		CollectedAt: collectedAt}
	if value.SourceTime != nil {
		observed, observedErr := observedTimeFromWire(*value.SourceTime)
		if observedErr != nil {
			return SourceInput{}, observedErr
		}
		result.SourceTime = &observed
	}
	if value.SourceRange != nil {
		start, startErr := observedTimeFromWire(value.SourceRange.Start)
		end, endErr := observedTimeFromWire(value.SourceRange.End)
		if startErr != nil {
			return SourceInput{}, startErr
		}
		if endErr != nil {
			return SourceInput{}, endErr
		}
		result.SourceRange = &SourceTimeRange{Start: start, End: end}
	}
	return result, nil
}

func manifestFromWire(value manifestWire) (ArtifactManifest, error) {
	source, err := sourceFromWire(value.Source)
	if err != nil {
		return ArtifactManifest{}, err
	}
	createdAt, err := parseTime(value.CreatedAt)
	if err != nil {
		return ArtifactManifest{}, err
	}
	parents := make([]domain.ArtifactRef, len(value.ParentArtifacts))
	for index := range value.ParentArtifacts {
		parents[index] = artifactFromWire(value.ParentArtifacts[index])
	}
	components := make([]ComponentVersion, len(value.Components))
	for index := range value.Components {
		components[index] = ComponentVersion(value.Components[index])
	}
	return ArtifactManifest{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		ManifestID: value.ManifestID, Case: caseFromWire(value.Case), Artifact: artifactFromWire(value.Artifact),
		Source: source, ParentArtifacts: parents,
		ParentManifestDigests: append([]string(nil), value.ParentManifestDigests...), Components: components,
		ActorID: value.ActorID, ActorRevision: value.ActorRevision, PolicyDigest: value.PolicyDigest,
		AuthorizationDigest: value.AuthorizationDigest, DecisionDigest: value.DecisionDigest,
		RevocationDigest: value.RevocationDigest, TransportDigest: value.TransportDigest,
		EncryptionContextDigest: value.EncryptionContextDigest, AuditEventDigest: value.AuditEventDigest,
		PreviousProvenanceDigest: clonePointer(value.PreviousProvenanceDigest),
		ProvenanceDigest:         value.ProvenanceDigest, CreatedAt: createdAt, Revision: value.Revision}, nil
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
