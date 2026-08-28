package command

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/capabilityseam"
	"github.com/ArronJablonowski/COH/internal/domain/profilecomposition"
)

type ProfileCapabilityArtifact struct {
	Reference profilecomposition.ArtifactRef
	Bundle    capabilityseam.ValidatedBundle
}

// PreparedProfileCapabilities exposes the combined bundle digest needed for a
// live qualification snapshot while retaining no executable capability.
type PreparedProfileCapabilities struct {
	candidate profilecomposition.Candidate
	bundle    capabilityseam.ValidatedBundle
}

func (prepared PreparedProfileCapabilities) BundleDigest() string { return prepared.bundle.Digest() }
func (prepared PreparedProfileCapabilities) ProfileBindingDigest() string {
	return prepared.candidate.ProfileBindingDigest()
}

// PrepareProfileCapabilities closes signed declarations without publishing a
// graph or activating a provider.
func PrepareProfileCapabilities(ctx context.Context, candidate profilecomposition.Candidate,
	artifacts []ProfileCapabilityArtifact) (PreparedProfileCapabilities, error) {
	if err := profileCompositionContextError(ctx); err != nil {
		return PreparedProfileCapabilities{}, err
	}
	request := candidate.Request()
	references := candidate.CapabilityReferences()
	if request.ProfileID == "" || candidate.ProfileBindingDigest() == "" {
		return PreparedProfileCapabilities{}, profilecomposition.NewError(profilecomposition.InvalidInput, "candidate_required")
	}
	if len(artifacts) != len(references) {
		return PreparedProfileCapabilities{}, profilecomposition.NewError(profilecomposition.Denied, "capability_artifacts_incomplete")
	}
	byID := make(map[string]ProfileCapabilityArtifact, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Reference.ID == "" || artifact.Reference.Revision == 0 || artifact.Bundle.Digest() == "" ||
			artifact.Bundle.Digest() != artifact.Reference.Digest {
			return PreparedProfileCapabilities{}, profilecomposition.NewError(profilecomposition.Denied, "capability_artifact")
		}
		if _, exists := byID[artifact.Reference.ID]; exists {
			return PreparedProfileCapabilities{}, profilecomposition.NewError(profilecomposition.Denied, "capability_artifact_ambiguous")
		}
		byID[artifact.Reference.ID] = artifact
	}
	combined := capabilityseam.Bundle{SchemaVersion: capabilityseam.BundleSchemaVersion,
		ContractVersion: capabilityseam.ContractVersion, BundleID: "profile." + request.ProfileID,
		Revision: request.Revision, ProfileDigest: candidate.ProfileBindingDigest()}
	for _, reference := range references {
		artifact, exists := byID[reference.ID]
		if !exists || artifact.Reference != reference {
			return PreparedProfileCapabilities{}, profilecomposition.NewError(profilecomposition.Denied, "capability_artifact_missing")
		}
		bundle := artifact.Bundle.Value()
		if bundle.BundleID != reference.ID || bundle.Revision != reference.Revision ||
			bundle.ProfileDigest != candidate.ProfileBindingDigest() {
			return PreparedProfileCapabilities{}, profilecomposition.NewError(profilecomposition.Denied, "capability_artifact_binding")
		}
		combined.Definitions = append(combined.Definitions, bundle.Definitions...)
		combined.Providers = append(combined.Providers, bundle.Providers...)
		combined.Consumers = append(combined.Consumers, bundle.Consumers...)
	}
	slices.SortFunc(combined.Definitions, func(left, right capabilityseam.Definition) int {
		return compareProfileText(left.Capability.Name+"@"+left.Capability.Version,
			right.Capability.Name+"@"+right.Capability.Version)
	})
	slices.SortFunc(combined.Providers, func(left, right capabilityseam.Provider) int {
		return compareProfileText(left.ProviderID, right.ProviderID)
	})
	slices.SortFunc(combined.Consumers, func(left, right capabilityseam.Consumer) int {
		return compareProfileText(left.ConsumerID, right.ConsumerID)
	})
	encoded, err := json.Marshal(combined)
	if err != nil {
		return PreparedProfileCapabilities{}, profilecomposition.NewError(profilecomposition.Denied, "capability_bundle_encoding")
	}
	bundle, err := capabilityseam.DecodeBundle(ctx, encoded)
	if err != nil {
		return PreparedProfileCapabilities{}, mapProfileCapabilityError(err)
	}
	return PreparedProfileCapabilities{candidate: candidate, bundle: bundle}, nil
}

func profileCompositionContextError(ctx context.Context) error {
	if ctx == nil {
		return profilecomposition.NewError(profilecomposition.InvalidInput, "context_missing")
	}
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return profilecomposition.NewError(profilecomposition.Timeout, "deadline_exceeded")
		}
		return profilecomposition.NewError(profilecomposition.Canceled, "context_canceled")
	default:
		return nil
	}
}

// Resolve verifies current qualification authority, publishes one closed graph,
// and binds it into the resolved profile. It performs no activation.
func (prepared PreparedProfileCapabilities) Resolve(ctx context.Context, clock profilecomposition.Clock,
	authority capabilityseam.QualificationAuthoritySnapshot,
) (profilecomposition.ValidatedResolvedProfile, capabilityseam.ValidatedGraph, error) {
	if prepared.bundle.Digest() == "" || prepared.candidate.ProfileBindingDigest() == "" {
		return profilecomposition.ValidatedResolvedProfile{}, capabilityseam.ValidatedGraph{},
			profilecomposition.NewError(profilecomposition.InvalidInput, "prepared_capabilities_required")
	}
	resolver, err := capabilityseam.NewResolver(clock)
	if err != nil {
		return profilecomposition.ValidatedResolvedProfile{}, capabilityseam.ValidatedGraph{},
			profilecomposition.NewError(profilecomposition.InvalidInput, "clock_missing")
	}
	graph, err := resolver.Resolve(ctx, prepared.bundle, authority)
	if err != nil {
		return profilecomposition.ValidatedResolvedProfile{}, capabilityseam.ValidatedGraph{}, mapProfileCapabilityError(err)
	}
	resolved, err := prepared.candidate.Finalize(ctx, graph.Digest())
	if err != nil {
		return profilecomposition.ValidatedResolvedProfile{}, capabilityseam.ValidatedGraph{}, err
	}
	return resolved, graph, nil
}

func mapProfileCapabilityError(err error) error {
	code := profilecomposition.Denied
	switch string(capabilityseam.Code(err)) {
	case "invalid_input":
		code = profilecomposition.InvalidInput
	case "canceled":
		code = profilecomposition.Canceled
	case "timeout":
		code = profilecomposition.Timeout
	case "unsupported":
		code = profilecomposition.Unsupported
	}
	reason := capabilityseam.Reason(err)
	if reason == "" {
		reason = "failed"
	}
	return profilecomposition.NewError(code, "capability_"+reason)
}

func compareProfileText(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
