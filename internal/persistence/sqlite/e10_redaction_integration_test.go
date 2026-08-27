package sqlite_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/persistence/encryptedcas"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/lifecycleredaction"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
	"github.com/ArronJablonowski/COH/internal/workflow/redactioncustody"
)

func composeE10DerivedRedaction(t *testing.T, now time.Time, sourceCommand evidenceingest.Command,
	ingestion *evidenceingest.Controller, receipts *evidenceingest.RepositoryStore, nativeCAS *encryptedcas.Store,
	repository workflow.MetadataStore, custodyController *custody.Controller, ledger *custody.RepositoryStore,
	evidence lifecycleCustodyEvidence, sourceEntry evidencelifecycle.ManifestArtifact,
	initialHead evidencelifecycle.CustodyHead, sourceBytes, derivedBytes []byte) (
	evidencelifecycle.ManifestArtifact, *lifecycleredaction.Adapter, evidencelifecycle.CustodyHead) {
	t.Helper()
	derivedCommand := e10DerivedIngestionCommand(sourceCommand, sourceEntry.Reference, derivedBytes, now)
	derived, err := ingestion.Execute(t.Context(), derivedCommand, &evidenceSource{value: derivedBytes})
	if err != nil {
		t.Fatalf("derived ingestion parents=%+v manifests=%+v components=%+v: %v", derivedCommand.ParentArtifacts,
			derivedCommand.ParentManifestDigests, derivedCommand.Components, err)
	}
	derivedReference := evidencelifecycle.EvidenceReference{Artifact: derived.Artifact, Manifest: derived.Manifest,
		ManifestProvenanceDigest: derived.Receipt.ManifestProvenanceDigest,
		IngestionReceiptDigest:   derived.Receipt.ReceiptDigest}
	redactionSource := toRedactionReference(sourceEntry.Reference)
	mapping := e10RedactionMapping(t, now, sourceCommand.Case, redactionSource, derived.Artifact, sourceBytes)
	mappingBytes, err := redaction.CanonicalMapping(mapping)
	if err != nil {
		t.Fatal(err)
	}
	mappingCommand := e10MappingIngestionCommand(sourceCommand, sourceEntry.Reference,
		derivedReference, mappingBytes, now)
	mappingResult, err := ingestion.Execute(t.Context(), mappingCommand, &evidenceSource{value: mappingBytes})
	if err != nil {
		t.Fatalf("mapping ingestion parents=%+v manifests=%+v components=%+v: %v", mappingCommand.ParentArtifacts,
			mappingCommand.ParentManifestDigests, mappingCommand.Components, err)
	}
	mappingReference := toRedactionReference(evidencelifecycle.EvidenceReference{
		Artifact: mappingResult.Artifact, Manifest: mappingResult.Manifest,
		ManifestProvenanceDigest: mappingResult.Receipt.ManifestProvenanceDigest,
		IngestionReceiptDigest:   mappingResult.Receipt.ReceiptDigest})
	derivedRedactionReference := toRedactionReference(derivedReference)
	evidence.verified[toCustodyReference(derivedReference)] = custody.VerifiedEvidence{
		Reference: toCustodyReference(derivedReference), SourceIdentityDigest: derivedCommand.Source.IdentityDigest,
		ParentArtifacts:       []domain.ArtifactRef{sourceEntry.Reference.Artifact},
		ParentManifestDigests: []string{sourceEntry.Reference.Manifest.Digest},
		VerificationDigest:    caseDigest("e10-derived-custody-verification")}

	command := redaction.Command{SchemaVersion: redaction.CommandSchemaVersion,
		ContractVersion: redaction.ContractVersion, RequestID: caseUUID("e10-redaction-request"),
		IdempotencyKey: "coh-e10-derived-redaction", Case: sourceCommand.Case, ActorID: sourceCommand.ActorID,
		ActorRevision: sourceCommand.ActorRevision, Source: redactionSource, RuleDigest: mapping.RuleDigest,
		PlanDigest: mapping.PlanDigest, ReasonDigest: mapping.ReasonDigest,
		OutputMediaType: derived.Artifact.MediaType, OutputClassification: derived.Artifact.Classification,
		KeyProfile: sourceCommand.KeyProfile, KeyProfileDigest: sourceCommand.KeyProfileDigest,
		PolicyDigest: caseDigest("e10-redaction-policy"), ExpectedCaseRevision: 1,
		ExpectedCustodyHead: toRedactionHead(initialHead), Deadline: now.Add(time.Hour)}
	decisionDigest, approvalDigest := caseDigest("e10-redaction-decision"), mapping.ApprovalFingerprintDigest
	custodyAdapter, err := redactioncustody.New(custodyController, ledger)
	if err != nil {
		t.Fatal(err)
	}
	custodyProof, replayed, err := custodyAdapter.RecordRedaction(t.Context(), redaction.CustodyRequest{
		Command: command, Derived: derivedRedactionReference, MappingDigest: mapping.MappingDigest,
		ApprovalDigest: approvalDigest, DecisionDigest: decisionDigest,
		ExpectedHead: command.ExpectedCustodyHead, Deadline: command.Deadline})
	if err != nil || replayed {
		t.Fatalf("redaction custody replayed=%v err=%v", replayed, err)
	}
	record, receipt := commitE10Redaction(t, now, repository, command, derivedRedactionReference,
		mappingReference, mapping, custodyProof, decisionDigest, approvalDigest)
	auditor := &e10RedactionAuditor{eventID: redaction.CompletedAuditEventID(record.RedactionID),
		proof: redaction.AuditProof{EventDigest: record.AuditEventDigest, Sequence: 50,
			ChainHash: caseDigest("e10-redaction-audit-chain")}}
	redactionRepository, err := redaction.NewRepositoryStore(repository)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleAdapter, err := lifecycleredaction.New(redactionRepository, receipts, nativeCAS, ledger,
		custodyAdapter, auditor)
	if err != nil {
		t.Fatal(err)
	}
	entry := evidencelifecycle.ManifestArtifact{Ordinal: 2, Role: evidencelifecycle.DerivedArtifact,
		Reference: derivedReference, ParentArtifactDigests: []string{sourceEntry.Reference.Artifact.Digest},
		ParentManifestDigests:  []string{sourceEntry.Reference.Manifest.Digest},
		RedactionReceiptDigest: &receipt.ReceiptDigest, MappingDigest: &mapping.MappingDigest}
	head, err := ledger.LoadHead(t.Context(), sourceCommand.Case)
	if err != nil {
		t.Fatal(err)
	}
	return entry, lifecycleAdapter, evidencelifecycle.CustodyHead{Case: head.Case, Sequence: head.Sequence,
		ChainHash: head.ChainHash, LastRecordAt: head.LastRecordAt}
}

func e10DerivedIngestionCommand(source evidenceingest.Command,
	parent evidencelifecycle.EvidenceReference, payload []byte, now time.Time) evidenceingest.Command {
	result := source
	result.RequestID, result.IdempotencyKey = caseUUID("e10-derived-ingestion"), "coh-e10-derived-ingestion"
	result.ExpectedDigest, result.ExpectedLength = evidenceDigest(payload), int64(len(payload))
	result.Source.Kind, result.Source.Identity = evidenceingest.DerivedSource, "coh-redaction:e10-derived"
	result.Source.IdentityDigest = evidenceingest.SourceIdentityDigest(result.Source.Identity)
	result.Source.CollectionMethod, result.Source.CollectionMethodVersion = "governed_redaction", redaction.ContractVersion
	result.Source.CollectedAt = now
	result.ParentArtifacts = []domain.ArtifactRef{parent.Artifact}
	result.ParentManifestDigests = []string{parent.Manifest.Digest}
	return result
}

func e10MappingIngestionCommand(source evidenceingest.Command, original,
	derived evidencelifecycle.EvidenceReference, payload []byte, now time.Time) evidenceingest.Command {
	result := source
	result.RequestID, result.IdempotencyKey = caseUUID("e10-mapping-ingestion"), "coh-e10-mapping-ingestion"
	result.ExpectedDigest, result.ExpectedLength = evidenceDigest(payload), int64(len(payload))
	result.MediaType = "application/vnd.coh.redaction-mapping+json"
	result.Source.Kind, result.Source.Identity = evidenceingest.DerivedSource, "coh-redaction:e10-mapping"
	result.Source.IdentityDigest = evidenceingest.SourceIdentityDigest(result.Source.Identity)
	result.Source.CollectionMethod, result.Source.CollectionMethodVersion = "governed_redaction", redaction.ContractVersion
	result.Source.CollectedAt = now
	parents := []evidencelifecycle.EvidenceReference{original, derived}
	sort.Slice(parents, func(i, j int) bool { return parents[i].Artifact.Digest < parents[j].Artifact.Digest })
	result.ParentArtifacts, result.ParentManifestDigests = make([]domain.ArtifactRef, 2), make([]string, 2)
	for index := range parents {
		result.ParentArtifacts[index], result.ParentManifestDigests[index] = parents[index].Artifact, parents[index].Manifest.Digest
	}
	return result
}

func e10RedactionMapping(t *testing.T, now time.Time, scope domain.CaseRef,
	source redaction.EvidenceReference, derived domain.ArtifactRef, sourceBytes []byte) redaction.Mapping {
	t.Helper()
	selected, replacement := sourceBytes[:6], []byte("******")
	value := redaction.Mapping{SchemaVersion: redaction.MappingSchemaVersion,
		ContractVersion: redaction.ContractVersion, MappingID: caseUUID("e10-redaction-mapping"),
		Case: scope, Source: source, DerivedArtifact: derived, PlanDigest: caseDigest("e10-redaction-plan"),
		RuleDigest: caseDigest("e10-redaction-rule"), ReasonDigest: caseDigest("e10-redaction-reason"),
		ApprovalFingerprintDigest: caseDigest("e10-redaction-approval"),
		Entries: []redaction.MappingEntry{{Ordinal: 1, SourceStart: 0, SourceEnd: 6,
			SourceSegmentDigest: evidenceDigest(selected), OutputStart: 0, OutputEnd: 6,
			ReplacementMode: redaction.Mask, ReplacementDigest: evidenceDigest(replacement)}},
		CreatedAt: now, PreviousProvenanceDigest: source.ManifestProvenanceDigest}
	value.ProvenanceDigest, _ = redaction.MappingProvenanceDigest(value)
	value.MappingDigest, _ = redaction.MappingBindingDigest(value)
	if err := redaction.ValidateMapping(value); err != nil {
		t.Fatalf("invalid E10 redaction mapping: %v", err)
	}
	return value
}

func commitE10Redaction(t *testing.T, now time.Time, repository workflow.MetadataStore,
	command redaction.Command, derived, mappingReference redaction.EvidenceReference, mapping redaction.Mapping,
	custodyProof redaction.CustodyProof, decisionDigest, approvalDigest string) (redaction.Record, redaction.Receipt) {
	t.Helper()
	store, err := redaction.NewRepositoryStore(repository)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := redaction.IntentBindingDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	idempotency, err := redaction.IdempotencyBindingDigest(command.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	publishedDerived := redaction.PublishedEvidence{Reference: derived, ReceiptDigest: derived.IngestionReceiptDigest}
	publishedMapping := redaction.PublishedEvidence{Reference: mappingReference,
		ReceiptDigest: mappingReference.IngestionReceiptDigest}
	phases := []redaction.Progress{
		{Case: command.Case, IdempotencyDigest: idempotency, IntentDigest: intent, Phase: redaction.PhasePlanned,
			Revision: 1, PlanDigest: command.PlanDigest, DecisionDigest: decisionDigest,
			ApprovalUseDigest: approvalDigest, UpdatedAt: now},
		{Case: command.Case, IdempotencyDigest: idempotency, IntentDigest: intent, Phase: redaction.PhasePublished,
			Revision: 2, PlanDigest: command.PlanDigest, DecisionDigest: decisionDigest,
			ApprovalUseDigest: approvalDigest, Derived: &publishedDerived, Mapping: &publishedMapping,
			MappingDigest: &mapping.MappingDigest, UpdatedAt: now.Add(time.Nanosecond)},
		{Case: command.Case, IdempotencyDigest: idempotency, IntentDigest: intent, Phase: redaction.PhaseCustodied,
			Revision: 3, PlanDigest: command.PlanDigest, DecisionDigest: decisionDigest,
			ApprovalUseDigest: approvalDigest, Derived: &publishedDerived, Mapping: &publishedMapping,
			MappingDigest: &mapping.MappingDigest, Custody: &custodyProof, UpdatedAt: now.Add(2 * time.Nanosecond)},
	}
	advanceRedactionPhases(t, store, command.IdempotencyKey, phases)
	record := redaction.Record{SchemaVersion: redaction.RecordSchemaVersion, ContractVersion: redaction.ContractVersion,
		RedactionID: caseUUID("e10-redaction-record"), Case: command.Case, Command: command, IntentDigest: intent,
		PlanDigest: command.PlanDigest, DecisionDigest: decisionDigest, RevocationDigest: caseDigest("e10-redaction-revocation"),
		ApprovalUseDigest: approvalDigest, SourceVerificationDigest: caseDigest("e10-redaction-source-verification"),
		Derived: derived, DerivedIngestionReceiptDigest: derived.IngestionReceiptDigest,
		MappingReference: mappingReference, MappingDigest: mapping.MappingDigest,
		MappingIngestionReceiptDigest: mappingReference.IngestionReceiptDigest,
		CustodyReceiptDigest:          custodyProof.ReceiptDigest, AuditEventDigest: caseDigest("e10-redaction-audit"),
		CreatedAt: phases[2].UpdatedAt, PreviousProvenanceDigest: command.Source.ManifestProvenanceDigest}
	record.ProvenanceDigest, _ = redaction.RecordProvenanceDigest(record)
	record.RecordDigest, _ = redaction.RecordBindingDigest(record)
	if err = redaction.ValidateRecord(record); err != nil {
		t.Fatalf("invalid E10 redaction record: %v", err)
	}
	receipt := redaction.Receipt{SchemaVersion: redaction.ReceiptSchemaVersion,
		ContractVersion: redaction.ContractVersion, RequestID: command.RequestID, Case: command.Case,
		IdempotencyDigest: idempotency, IntentDigest: intent, RedactionID: record.RedactionID,
		RecordDigest: record.RecordDigest, Derived: derived, MappingReference: mappingReference,
		MappingDigest: mapping.MappingDigest, CustodyReceiptDigest: custodyProof.ReceiptDigest,
		AuditEventDigest: record.AuditEventDigest, ProvenanceDigest: record.ProvenanceDigest, CreatedAt: record.CreatedAt}
	receipt.ReceiptDigest, _ = redaction.ReceiptBindingDigest(receipt)
	stored, _, err := store.Commit(t.Context(), command.IdempotencyKey, intent, record, receipt)
	if err != nil || stored.ReceiptDigest != receipt.ReceiptDigest {
		t.Fatalf("redaction commit=%+v err=%v", stored, err)
	}
	return record, receipt
}

func toRedactionReference(value evidencelifecycle.EvidenceReference) redaction.EvidenceReference {
	return redaction.EvidenceReference{Artifact: value.Artifact, Manifest: value.Manifest,
		ManifestProvenanceDigest: value.ManifestProvenanceDigest,
		IngestionReceiptDigest:   value.IngestionReceiptDigest}
}

func toRedactionHead(value evidencelifecycle.CustodyHead) redaction.CustodyHead {
	return redaction.CustodyHead{Case: value.Case, Sequence: value.Sequence,
		ChainHash: value.ChainHash, LastRecordAt: value.LastRecordAt}
}

type e10RedactionAuditor struct {
	eventID string
	proof   redaction.AuditProof
}

func (auditor *e10RedactionAuditor) VerifyRedactionEvent(_ context.Context, _ domain.CaseRef,
	eventID, eventDigest string) (redaction.AuditProof, error) {
	if eventID != auditor.eventID || eventDigest != auditor.proof.EventDigest {
		return redaction.AuditProof{}, errors.New("redaction audit proof mismatch")
	}
	return auditor.proof, nil
}
