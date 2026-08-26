// Package opaengine verifies and evaluates signed Open Policy Agent bundles.
package opaengine

import (
	"crypto/ed25519"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
)

const (
	BundleSchemaVersion   = "coh.opa-policy-bundle/v1"
	EnvelopeSchemaVersion = "coh.signed-opa-policy-bundle/v1"
	BundleContractVersion = "1.0.0"
	DecisionEntrypoint    = "data.coh.authz.decision"
	SignatureAlgorithm    = "ed25519"
	SignatureDomain       = "COH-SIGNED-OPA-POLICY-V1\x00"
	MaximumBundleBytes    = 1 << 20
	MaximumModuleBytes    = 256 << 10
	MaximumBundleModules  = 32
	MaximumBundleValidity = 30 * 24 * time.Hour
	auditAppendTimeout    = 5 * time.Second
)

type bundleMetadata struct {
	SchemaVersion     string `json:"schema_version"`
	ContractVersion   string `json:"contract_version"`
	BundleID          string `json:"bundle_id"`
	OrganizationID    string `json:"organization_id"`
	TenantID          string `json:"tenant_id"`
	PolicyRevision    uint64 `json:"policy_revision"`
	Entrypoint        string `json:"entrypoint"`
	ValidFrom         string `json:"valid_from"`
	ValidUntil        string `json:"valid_until"`
	SignerKeyID       string `json:"-"`
	SignerKeyRevision uint64 `json:"-"`
	SignerKeyDigest   string `json:"-"`
}

type bundleModule struct {
	Path   string `json:"path"`
	Source string `json:"source"`
}

type policyBundle struct {
	bundleMetadata
	Modules []bundleModule `json:"modules"`
	Data    map[string]any `json:"data"`
}

type signedBundleEnvelope struct {
	SchemaVersion      string       `json:"schema_version"`
	ContractVersion    string       `json:"contract_version"`
	Bundle             policyBundle `json:"bundle"`
	BundleDigest       string       `json:"bundle_digest"`
	SignerKeyID        string       `json:"signer_key_id"`
	SignerKeyRevision  uint64       `json:"signer_key_revision"`
	SignatureAlgorithm string       `json:"signature_algorithm"`
	Signature          string       `json:"signature"`
}

type snapshot struct {
	compiler   *ast.Compiler
	query      ast.Body
	store      storage.Store
	metadata   bundleMetadata
	digest     string
	validFrom  time.Time
	validUntil time.Time
}

func signatureMessage(canonicalBundle []byte) []byte {
	message := make([]byte, 0, len(SignatureDomain)+len(canonicalBundle))
	message = append(message, SignatureDomain...)
	return append(message, canonicalBundle...)
}

func verifySignature(publicKey ed25519.PublicKey, canonicalBundle, signature []byte) bool {
	return ed25519.Verify(publicKey, signatureMessage(canonicalBundle), signature)
}

type Engine struct {
	audit  policy.AuditSink
	clock  policy.Clock
	loadMu sync.Mutex
	active atomic.Pointer[snapshot]
}

func New(audit policy.AuditSink, clock policy.Clock) (*Engine, error) {
	if audit == nil || clock == nil {
		return nil, policy.NewError(policy.InvalidInput, "engine_dependencies")
	}
	return &Engine{audit: audit, clock: clock}, nil
}

type policyOutput struct {
	Allow            bool   `json:"allow"`
	ReasonCode       string `json:"reason_code"`
	ApprovalRequired bool   `json:"approval_required"`
}
