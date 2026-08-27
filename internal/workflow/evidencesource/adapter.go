// Package evidencesource resolves lifecycle artifact references to exact,
// receipt-bound encrypted CAS plaintext streams.
package evidencesource

import (
	"context"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

type ReceiptResolver interface {
	ResolveReceipt(context.Context, domain.CaseRef, string) (evidenceingest.Receipt, bool, error)
}

type ArtifactOpener interface {
	OpenIngestedArtifact(context.Context, evidenceingest.Receipt) (io.ReadCloser, error)
}

type Adapter struct {
	receipts  ReceiptResolver
	artifacts ArtifactOpener
}

func New(receipts ReceiptResolver, artifacts ArtifactOpener) (*Adapter, error) {
	if receipts == nil || artifacts == nil {
		return nil, errors.New("evidence source dependencies are required")
	}
	return &Adapter{receipts: receipts, artifacts: artifacts}, nil
}

func (adapter *Adapter) OpenArtifact(ctx context.Context, scope domain.CaseRef,
	reference evidencelifecycle.EvidenceReference) (io.ReadCloser, error) {
	if ctx == nil || reference.IngestionReceiptDigest == "" {
		return nil, errors.New("evidence source request is invalid")
	}
	receipt, found, err := adapter.receipts.ResolveReceipt(ctx, scope, reference.IngestionReceiptDigest)
	if err != nil {
		return nil, errors.New("evidence source receipt is unavailable")
	}
	if !found || receipt.Case != scope || receipt.ReceiptDigest != reference.IngestionReceiptDigest ||
		receipt.Artifact != reference.Artifact || receipt.Manifest != reference.Manifest ||
		receipt.ManifestProvenanceDigest != reference.ManifestProvenanceDigest {
		return nil, errors.New("evidence source receipt binding is invalid")
	}
	reader, err := adapter.artifacts.OpenIngestedArtifact(ctx, receipt)
	if err != nil {
		return nil, errors.New("evidence source artifact is unavailable")
	}
	return reader, nil
}
