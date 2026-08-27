// Package lifecycledisposition adapts governed evidence deletion to exact
// encrypted-CAS object removal and durable disposition attestations.
package lifecycledisposition

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

const (
	repositorySchema = "coh.domain/v1"
	repositoryKind   = "lifecycle_disposition"
)

type ReceiptResolver interface {
	ResolveReceipt(context.Context, domain.CaseRef, string) (evidenceingest.Receipt, bool, error)
}

type EncryptedCAS interface {
	Resolve(context.Context, evidenceingest.PublishedObject) (evidenceingest.EncryptedObject, error)
	DisposePublished(context.Context, evidenceingest.PublishedObject, string, uint64) (bool, error)
}

type Clock interface{ Now() time.Time }

type Adapter struct {
	receipts   ReceiptResolver
	cas        EncryptedCAS
	repository workflowbase.MetadataStore
	clock      Clock
}

type storedOperation struct {
	Case                              domain.CaseRef                            `json:"case"`
	OperationID                       string                                    `json:"operation_id"`
	RequestDigest                     string                                    `json:"request_digest"`
	ArtifactSetDigest                 string                                    `json:"artifact_set_digest"`
	AuthorizationCustodyReceiptDigest string                                    `json:"authorization_custody_receipt_digest"`
	LifecycleReceiptDigest            string                                    `json:"lifecycle_receipt_digest"`
	AttemptedAt                       time.Time                                 `json:"attempted_at"`
	Objects                           []plannedObject                           `json:"objects"`
	Attestation                       *evidencelifecycle.DispositionAttestation `json:"attestation"`
}

type plannedObject struct {
	ArtifactDigest         string                         `json:"artifact_digest"`
	IngestionReceiptDigest string                         `json:"ingestion_receipt_digest"`
	Reference              evidenceingest.PublishedObject `json:"reference"`
	EncryptedObjectDigest  string                         `json:"encrypted_object_digest"`
	KeyRevision            uint64                         `json:"key_revision"`
}

type envelope struct {
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
