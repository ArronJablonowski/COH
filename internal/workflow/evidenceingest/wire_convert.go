package evidenceingest

import "github.com/ArronJablonowski/COH/internal/domain"

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func artifactToWire(value domain.ArtifactRef) artifactWire {
	return artifactWire{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func transportToWire(value TransportContext) transportWire {
	return transportWire(value)
}

func observedTimeToWire(value ObservedTime) observedTimeWire {
	return observedTimeWire{Value: formatTime(value.Value), OriginalOffsetMinutes: value.OriginalOffsetMinutes,
		Precision: value.Precision, UncertaintyNanos: value.UncertaintyNanos}
}

func observedTimePointerToWire(value *ObservedTime) *observedTimeWire {
	if value == nil {
		return nil
	}
	result := observedTimeToWire(*value)
	return &result
}

func sourceRangeToWire(value *SourceTimeRange) *sourceRangeWire {
	if value == nil {
		return nil
	}
	return &sourceRangeWire{Start: observedTimeToWire(value.Start), End: observedTimeToWire(value.End)}
}

func sourceToWire(value SourceInput) sourceWire {
	return sourceWire{Kind: value.Kind, Identity: value.Identity, IdentityDigest: value.IdentityDigest,
		CollectionMethod: value.CollectionMethod, CollectionMethodVersion: value.CollectionMethodVersion,
		CollectedAt: formatTime(value.CollectedAt), SourceTime: observedTimePointerToWire(value.SourceTime),
		SourceRange: sourceRangeToWire(value.SourceRange)}
}

func componentToWire(value ComponentVersion) componentWire {
	return componentWire(value)
}

func artifactsToWire(values []domain.ArtifactRef) []artifactWire {
	result := make([]artifactWire, len(values))
	for index, value := range values {
		result[index] = artifactToWire(value)
	}
	return result
}

func componentsToWire(values []ComponentVersion) []componentWire {
	result := make([]componentWire, len(values))
	for index, value := range values {
		result[index] = componentToWire(value)
	}
	return result
}

func commandToWire(value Command) commandWire {
	return commandWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, IdempotencyKey: value.IdempotencyKey, Case: caseToWire(value.Case),
		ActorID: value.ActorID, ActorRevision: value.ActorRevision, ExpectedDigest: value.ExpectedDigest,
		ExpectedLength: value.ExpectedLength, MediaType: value.MediaType, Classification: value.Classification,
		Source: sourceToWire(value.Source), ParentArtifacts: artifactsToWire(value.ParentArtifacts),
		ParentManifestDigests: append([]string{}, value.ParentManifestDigests...),
		Components:            componentsToWire(value.Components), KeyProfile: value.KeyProfile,
		KeyProfileDigest: value.KeyProfileDigest, PolicyDigest: value.PolicyDigest,
		Transport: transportToWire(value.Transport), Deadline: formatTime(value.Deadline)}
}

func authorizationToWire(value AuthorizationRequest) authorizationWire {
	return authorizationWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		AuthorizationDigest: value.AuthorizationDigest, IntentDigest: value.IntentDigest,
		Command: commandToWire(value.Command), CaseRevision: value.CaseRevision, CaseState: value.CaseState,
		CaseClassification: value.CaseClassification, CaseProvenanceDigest: value.CaseProvenanceDigest}
}

func decisionToWire(value Decision) decisionWire {
	return decisionWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		DecisionID: value.DecisionID, DecisionDigest: value.DecisionDigest,
		AuthorizationDigest: value.AuthorizationDigest, IntentDigest: value.IntentDigest,
		Case: caseToWire(value.Case), ActorID: value.ActorID, ActorRevision: value.ActorRevision,
		ArtifactDigest: value.ArtifactDigest, ArtifactLength: value.ArtifactLength,
		PolicyDigest: value.PolicyDigest, KeyProfileDigest: value.KeyProfileDigest,
		TransportDigest: value.TransportDigest, RevocationDigest: value.RevocationDigest,
		Outcome: value.Outcome, ReasonCode: value.ReasonCode, IssuedAt: formatTime(value.IssuedAt),
		ExpiresAt: formatTime(value.ExpiresAt), Revision: value.Revision}
}

func manifestToWire(value ArtifactManifest) manifestWire {
	return manifestWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		ManifestID: value.ManifestID, Case: caseToWire(value.Case), Artifact: artifactToWire(value.Artifact),
		Source: sourceToWire(value.Source), ParentArtifacts: artifactsToWire(value.ParentArtifacts),
		ParentManifestDigests: append([]string{}, value.ParentManifestDigests...),
		Components:            componentsToWire(value.Components), ActorID: value.ActorID,
		ActorRevision: value.ActorRevision, PolicyDigest: value.PolicyDigest,
		AuthorizationDigest: value.AuthorizationDigest, DecisionDigest: value.DecisionDigest,
		RevocationDigest: value.RevocationDigest, TransportDigest: value.TransportDigest,
		EncryptionContextDigest: value.EncryptionContextDigest, AuditEventDigest: value.AuditEventDigest,
		PreviousProvenanceDigest: clonePointer(value.PreviousProvenanceDigest),
		ProvenanceDigest:         value.ProvenanceDigest, CreatedAt: formatTime(value.CreatedAt), Revision: value.Revision}
}

func encryptedObjectToWire(value EncryptedObject) encryptedObjectWire {
	return encryptedObjectWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		Status: value.Status, Case: caseToWire(value.Case), PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, CiphertextDigest: value.CiphertextDigest,
		CiphertextLength: value.CiphertextLength, MediaType: value.MediaType,
		Classification: value.Classification, EncryptionFormat: value.EncryptionFormat,
		ChunkSize: value.ChunkSize, ChunkCount: value.ChunkCount, KeyReference: value.KeyReference,
		KeyRevision: value.KeyRevision, KeyAlgorithm: value.KeyAlgorithm,
		WrappedKeyDigest: value.WrappedKeyDigest, EncryptionContextDigest: value.EncryptionContextDigest,
		LocatorDigest: value.LocatorDigest, CreatedAt: formatTime(value.CreatedAt)}
}

func publishedObjectToWire(value PublishedObject) publishedObjectWire {
	return publishedObjectWire{Case: caseToWire(value.Case), PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, CiphertextDigest: value.CiphertextDigest,
		CiphertextLength: value.CiphertextLength, EncryptionFormat: value.EncryptionFormat,
		EncryptionContextDigest: value.EncryptionContextDigest, LocatorDigest: value.LocatorDigest}
}

func receiptToWire(value Receipt) receiptWire {
	return receiptWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, Case: caseToWire(value.Case), ActorID: value.ActorID,
		ActorRevision: value.ActorRevision, IntentDigest: value.IntentDigest,
		IdempotencyDigest: value.IdempotencyDigest, AuthorizationDigest: value.AuthorizationDigest,
		DecisionDigest: value.DecisionDigest, RevocationDigest: value.RevocationDigest,
		TransportDigest: value.TransportDigest, Artifact: artifactToWire(value.Artifact),
		Manifest: artifactToWire(value.Manifest), EncryptedArtifact: publishedObjectToWire(value.EncryptedArtifact),
		EncryptedManifest:        publishedObjectToWire(value.EncryptedManifest),
		ManifestProvenanceDigest: value.ManifestProvenanceDigest,
		AuditEventDigest:         value.AuditEventDigest, CreatedAt: formatTime(value.CreatedAt),
		ReceiptDigest: value.ReceiptDigest}
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
