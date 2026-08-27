// Package importingest publishes verified, staged package artifacts through the
// sole immutable encrypted evidence-ingestion owner.
package importingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

type Ingestor interface {
	Execute(context.Context, evidenceingest.Command, evidenceingest.Source) (evidenceingest.Result, error)
}

type StagedSource interface {
	evidenceingest.Source
	Close() error
}

type StagedStore interface {
	OpenStaged(context.Context, evidencelifecycle.StagedImportArtifact) (StagedSource, error)
}

type Profile struct {
	KeyProfile       string
	KeyProfileDigest string
	Transport        evidenceingest.TransportContext
}

type Adapter struct {
	ingestor Ingestor
	staged   StagedStore
	profile  Profile
}

var (
	profileTokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	profileDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func New(ingestor Ingestor, staged StagedStore, profile Profile) (*Adapter, error) {
	if ingestor == nil || staged == nil || !profileTokenPattern.MatchString(profile.KeyProfile) ||
		!profileDigestPattern.MatchString(profile.KeyProfileDigest) {
		return nil, errors.New("import ingestion dependencies are invalid")
	}
	if _, err := evidenceingest.TransportBindingDigest(profile.Transport); err != nil {
		return nil, errors.New("import ingestion transport is invalid")
	}
	return &Adapter{ingestor: ingestor, staged: staged, profile: profile}, nil
}

func (adapter *Adapter) PublishImport(ctx context.Context,
	request evidencelifecycle.ImportPublicationRequest) (evidencelifecycle.PublishedImport, error) {
	if ctx == nil || request.RequestID == "" || request.IdempotencyKey == "" || len(request.Verified.Staged) == 0 ||
		len(request.Verified.Staged) != len(request.Verified.Manifest.Artifacts) {
		return evidencelifecycle.PublishedImport{}, errors.New("import publication request is invalid")
	}
	result := evidencelifecycle.PublishedImport{
		Artifacts: make([]evidencelifecycle.EvidenceReference, len(request.Verified.Staged)),
		Progress:  make([]evidencelifecycle.ArtifactProgress, len(request.Verified.Staged)),
	}
	published := make(map[string]evidencelifecycle.EvidenceReference, len(result.Artifacts))
	for index, staged := range request.Verified.Staged {
		artifact := request.Verified.Manifest.Artifacts[index]
		parents, parentManifests, err := localParents(artifact, published)
		if err != nil {
			return evidencelifecycle.PublishedImport{}, err
		}
		source, err := adapter.staged.OpenStaged(ctx, staged)
		if err != nil {
			return evidencelifecycle.PublishedImport{}, errors.New("staged import artifact is unavailable")
		}
		command := adapter.command(request, artifact, parents, parentManifests)
		ingested, ingestErr := adapter.ingestor.Execute(ctx, command, source)
		closeErr := source.Close()
		if ingestErr != nil {
			return evidencelifecycle.PublishedImport{}, ingestErr
		}
		if closeErr != nil {
			return evidencelifecycle.PublishedImport{}, errors.New("staged import artifact close failed")
		}
		if _, err = evidenceingest.CanonicalReceipt(ingested.Receipt); err != nil ||
			ingested.Artifact != artifact.Reference.Artifact || ingested.Receipt.Case != request.Case ||
			ingested.Receipt.ActorID != request.ActorID || ingested.Receipt.ActorRevision != request.ActorRevision ||
			ingested.Receipt.Artifact != ingested.Artifact || ingested.Receipt.Manifest != ingested.Manifest ||
			ingested.Receipt.ReceiptDigest == "" {
			return evidencelifecycle.PublishedImport{}, errors.New("import ingestion result is invalid")
		}
		reference := evidencelifecycle.EvidenceReference{Artifact: ingested.Artifact, Manifest: ingested.Manifest,
			ManifestProvenanceDigest: ingested.Receipt.ManifestProvenanceDigest,
			IngestionReceiptDigest:   ingested.Receipt.ReceiptDigest}
		result.Artifacts[index] = reference
		receiptDigest := ingested.Receipt.ReceiptDigest
		result.Progress[index] = evidencelifecycle.ArtifactProgress{Ordinal: artifact.Ordinal,
			ArtifactDigest: artifact.Reference.Artifact.Digest, IngestionReceiptDigest: &receiptDigest}
		published[reference.Artifact.Digest] = reference
	}
	return result, nil
}

func (adapter *Adapter) command(request evidencelifecycle.ImportPublicationRequest,
	artifact evidencelifecycle.ManifestArtifact, parents []domain.ArtifactRef, parentManifests []string) evidenceingest.Command {
	manifest := request.Verified.Manifest
	identity := "coh-import:" + request.Verified.Verification.SourceDigest + ":" +
		request.Verified.Package.PackageDigest + ":" + request.Verified.Verification.ReportDigest + ":" +
		artifact.Reference.Artifact.Digest
	return evidenceingest.Command{SchemaVersion: evidenceingest.CommandSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion,
		RequestID:       deterministicID(request.RequestID, artifact.Ordinal),
		IdempotencyKey:  deterministicKey(request.IdempotencyKey, artifact.Ordinal), Case: request.Case,
		ActorID: request.ActorID, ActorRevision: request.ActorRevision,
		ExpectedDigest: artifact.Reference.Artifact.Digest, ExpectedLength: artifact.Reference.Artifact.Length,
		MediaType: artifact.Reference.Artifact.MediaType, Classification: artifact.Reference.Artifact.Classification,
		Source: evidenceingest.SourceInput{Kind: evidenceingest.ImportSource, Identity: identity,
			IdentityDigest: evidenceingest.SourceIdentityDigest(identity), CollectionMethod: "signed_evidence_import",
			CollectionMethodVersion: evidencelifecycle.ContractVersion, CollectedAt: manifest.CreatedAt},
		ParentArtifacts: parents, ParentManifestDigests: parentManifests,
		Components: compatibleComponents(manifest.Components), KeyProfile: adapter.profile.KeyProfile,
		KeyProfileDigest: adapter.profile.KeyProfileDigest, PolicyDigest: request.PolicyDigest,
		Transport: adapter.profile.Transport, Deadline: request.Deadline}
}

func localParents(artifact evidencelifecycle.ManifestArtifact,
	published map[string]evidencelifecycle.EvidenceReference) ([]domain.ArtifactRef, []string, error) {
	parents := make([]domain.ArtifactRef, len(artifact.ParentArtifactDigests))
	manifests := make([]string, len(parents))
	for index, digest := range artifact.ParentArtifactDigests {
		parent, found := published[digest]
		if !found {
			return nil, nil, errors.New("import parent is not published")
		}
		parents[index], manifests[index] = parent.Artifact, parent.Manifest.Digest
	}
	sort.Slice(parents, func(left, right int) bool {
		if parents[left].Digest != parents[right].Digest {
			return parents[left].Digest < parents[right].Digest
		}
		if parents[left].MediaType != parents[right].MediaType {
			return parents[left].MediaType < parents[right].MediaType
		}
		return parents[left].Classification < parents[right].Classification
	})
	sort.Strings(manifests)
	return parents, manifests, nil
}

func compatibleComponents(values []evidencelifecycle.Component) []evidenceingest.ComponentVersion {
	result := make([]evidenceingest.ComponentVersion, 0, len(values))
	for _, value := range values {
		var kind evidenceingest.ComponentKind
		switch value.Kind {
		case "model":
			kind = evidenceingest.ModelComponent
		case "tool":
			kind = evidenceingest.ToolComponent
		case "query":
			kind = evidenceingest.QueryComponent
		default:
			continue
		}
		result = append(result, evidenceingest.ComponentVersion{Kind: kind, Name: value.Name,
			Version: value.Version, Digest: value.Digest})
	}
	return result
}

func deterministicKey(value string, ordinal uint16) string {
	sum := sha256.Sum256([]byte("COH-EVIDENCE-IMPORT-INGEST-IDEMPOTENCY-V1\x00" + value + "\x00" + fmt.Sprint(ordinal)))
	return "coh-import-" + hex.EncodeToString(sum[:])
}

func deterministicID(value string, ordinal uint16) string {
	sum := sha256.Sum256([]byte("COH-EVIDENCE-IMPORT-INGEST-REQUEST-ID-V1\x00" + value + "\x00" + fmt.Sprint(ordinal)))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

var _ evidencelifecycle.Publisher = (*Adapter)(nil)
