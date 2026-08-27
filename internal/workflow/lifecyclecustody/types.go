// Package lifecyclecustody adapts evidence lifecycle operations to the
// authoritative append-only custody controller, repository, and verifier.
package lifecyclecustody

import (
	"context"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/auditlog"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
)

const (
	repositorySchema = "coh.domain/v1"
	repositoryKind   = "lifecycle_custody_set"
)

type Controller interface {
	Execute(context.Context, custody.Command) (custody.Result, error)
	VerifyReceipt(context.Context, custody.Command, custody.Receipt) error
}

type Ledger interface {
	LoadHead(context.Context, domain.CaseRef) (custody.Head, error)
	Recover(context.Context, domain.CaseRef, string) (custody.Receipt, bool, error)
	ResolveReceipt(context.Context, domain.CaseRef, string) (custody.Receipt, bool, error)
	Read(context.Context, domain.CaseRef, uint64, uint16) ([]custody.Record, error)
}

type Verifier interface {
	VerifyInterval(context.Context, domain.CaseRef, uint64, uint64) (custody.VerificationReport, error)
}

type CheckpointResolver interface {
	ResolveCheckpointProof(context.Context, string, string, string, string, uint64) (auditlog.CheckpointProof, error)
}

type Adapter struct {
	controller  Controller
	ledger      Ledger
	verifier    Verifier
	checkpoints CheckpointResolver
	repository  workflowbase.MetadataStore
}

type storedSet struct {
	Case          domain.CaseRef
	RequestDigest string
	InitialHead   custody.Head
	Proofs        []storedProof
	SetDigest     string
}

type storedProof struct {
	ReceiptDigest string
	RecordDigest  string
	AuditDigest   string
	Sequence      uint64
	ChainHash     string
	CreatedAt     string
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
