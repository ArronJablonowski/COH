// Package evidencecatalog registers and resolves immutable, case-scoped sets
// of fully verified ingestion artifacts.
package evidencecatalog

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

const (
	recordSchema     = "coh.evidence-artifact-set/v1"
	recordContract   = "1.0.0"
	repositoryKind   = "evidence_artifact_set"
	repositorySchema = "coh.domain/v1"
)

type Registration struct {
	Case      domain.CaseRef
	Artifacts []evidencelifecycle.ManifestArtifact
}

type ReceiptResolver interface {
	ResolveReceipt(context.Context, domain.CaseRef, string) (evidenceingest.Receipt, bool, error)
}

type ManifestResolver interface {
	ResolveArtifactManifest(context.Context, evidenceingest.Receipt) (evidenceingest.ArtifactManifest, error)
}

type Catalog struct {
	repository workflowbase.MetadataStore
	receipts   ReceiptResolver
	manifests  ManifestResolver
}

func New(repository workflowbase.MetadataStore, receipts ReceiptResolver,
	manifests ManifestResolver) (*Catalog, error) {
	if repository == nil || receipts == nil || manifests == nil {
		return nil, lifecycleError(evidencelifecycle.InvalidInput, "catalog_dependencies_required", false)
	}
	return &Catalog{repository: repository, receipts: receipts, manifests: manifests}, nil
}

var _ evidencelifecycle.EvidenceResolver = (*Catalog)(nil)
