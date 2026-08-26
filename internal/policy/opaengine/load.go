package opaengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

func (engine *Engine) Load(ctx context.Context, input []byte, authority policy.BundleAuthority) (policy.Activation, error) {
	if engine == nil || engine.audit == nil || engine.clock == nil {
		return policy.Activation{}, policy.NewError(policy.Unavailable, "engine_unavailable")
	}
	if err := contextError(ctx); err != nil {
		return policy.Activation{}, err
	}
	if len(input) == 0 || len(input) > MaximumBundleBytes {
		return policy.Activation{}, policy.NewError(policy.InvalidInput, "bundle_size")
	}
	if err := validateAuthority(authority); err != nil {
		return policy.Activation{}, err
	}
	engine.loadMu.Lock()
	defer engine.loadMu.Unlock()
	if err := contextError(ctx); err != nil {
		return policy.Activation{}, err
	}
	envelope, canonicalBundle, err := decodeAndVerifyBundle(input, authority)
	if err != nil {
		return policy.Activation{}, err
	}
	metadata := envelope.Bundle.bundleMetadata
	metadata.SignerKeyID, metadata.SignerKeyRevision = envelope.SignerKeyID, envelope.SignerKeyRevision
	metadata.SignerKeyDigest = digestBytes(authority.PublicKey)
	now := engine.clock.Now().UTC()
	if now.IsZero() {
		return policy.Activation{}, policy.NewError(policy.Unavailable, "clock_unavailable")
	}
	validFrom, _ := time.Parse(timestampLayout, metadata.ValidFrom)
	validUntil, _ := time.Parse(timestampLayout, metadata.ValidUntil)
	if now.Before(validFrom) || !now.Before(validUntil) {
		return policy.Activation{}, policy.NewError(policy.Denied, "bundle_not_current")
	}
	digest := digestBytes(canonicalBundle)
	current := engine.active.Load()
	if current != nil {
		if metadata.OrganizationID != current.metadata.OrganizationID || metadata.TenantID != current.metadata.TenantID {
			return policy.Activation{}, policy.NewError(policy.Denied, "bundle_scope_changed")
		}
		if metadata.PolicyRevision <= current.metadata.PolicyRevision {
			return policy.Activation{}, policy.NewError(policy.Denied, "bundle_revision_stale")
		}
	}
	compiler, query, err := compileBundle(envelope.Bundle)
	if err != nil {
		return policy.Activation{}, err
	}
	if err := contextError(ctx); err != nil {
		return policy.Activation{}, err
	}
	activation := policy.Activation{
		BundleID: metadata.BundleID, PolicyDigest: digest, PolicyRevision: metadata.PolicyRevision,
		SignerKeyID: metadata.SignerKeyID, SignerKeyRevision: metadata.SignerKeyRevision,
		ActivatedAt: now.Format(timestampLayout),
	}
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := engine.audit.AppendPolicyEvent(auditCtx, policy.AuditEvent{Kind: "policy_activation", Activation: &activation}); err != nil {
		return policy.Activation{}, policy.NewError(policy.Unavailable, "audit_unavailable")
	}
	engine.active.Store(&snapshot{compiler: compiler, query: query, store: inmem.NewFromObject(envelope.Bundle.Data),
		metadata: metadata, digest: digest, validFrom: validFrom, validUntil: validUntil})
	return activation, nil
}

func decodeAndVerifyBundle(input []byte, authority policy.BundleAuthority) (signedBundleEnvelope, []byte, error) {
	canonicalEnvelope, err := domaincontract.Canonicalize(input)
	if err != nil {
		return signedBundleEnvelope{}, nil, policy.NewError(policy.Denied, "bundle_verification_failed")
	}
	var envelope signedBundleEnvelope
	decoder := json.NewDecoder(bytes.NewReader(canonicalEnvelope))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return signedBundleEnvelope{}, nil, policy.NewError(policy.Denied, "bundle_verification_failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return signedBundleEnvelope{}, nil, policy.NewError(policy.Denied, "bundle_verification_failed")
	}
	if envelope.SchemaVersion != EnvelopeSchemaVersion || envelope.ContractVersion != BundleContractVersion ||
		envelope.SignerKeyID != authority.KeyID || envelope.SignerKeyRevision != authority.KeyRevision ||
		envelope.SignatureAlgorithm != SignatureAlgorithm {
		return signedBundleEnvelope{}, nil, policy.NewError(policy.Denied, "bundle_authority_mismatch")
	}
	if err := validateBundle(envelope.Bundle); err != nil {
		return signedBundleEnvelope{}, nil, err
	}
	bundleBytes, err := json.Marshal(envelope.Bundle)
	if err != nil {
		return signedBundleEnvelope{}, nil, policy.NewError(policy.Denied, "bundle_verification_failed")
	}
	canonicalBundle, err := domaincontract.Canonicalize(bundleBytes)
	if err != nil || envelope.BundleDigest != digestBytes(canonicalBundle) {
		return signedBundleEnvelope{}, nil, policy.NewError(policy.Denied, "bundle_verification_failed")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !verifySignature(authority.PublicKey, canonicalBundle, signature) {
		return signedBundleEnvelope{}, nil, policy.NewError(policy.Denied, "bundle_verification_failed")
	}
	return envelope, canonicalBundle, nil
}

func compileBundle(bundle policyBundle) (*ast.Compiler, ast.Body, error) {
	capabilities := policyCapabilities()
	modules := make(map[string]*ast.Module, len(bundle.Modules))
	for _, candidate := range bundle.Modules {
		module, err := ast.ParseModuleWithOpts(candidate.Path, candidate.Source, ast.ParserOptions{
			RegoVersion: ast.RegoV1, Capabilities: capabilities,
		})
		if err != nil {
			return nil, nil, policy.NewError(policy.Denied, "bundle_compile_failed")
		}
		modules[candidate.Path] = module
	}
	compiler := ast.NewCompiler().WithCapabilities(capabilities)
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, nil, policy.NewError(policy.Denied, "bundle_compile_failed")
	}
	query, err := compiler.QueryCompiler().Compile(ast.MustParseBody(DecisionEntrypoint + " = result"))
	if err != nil {
		return nil, nil, policy.NewError(policy.Denied, "bundle_compile_failed")
	}
	return compiler, query, nil
}

func auditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), auditAppendTimeout)
}
