package command

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/profileactivation"
	"github.com/ArronJablonowski/COH/internal/domain/profilecomposition"
)

// ActivateResolvedProfile converts only fully sealed composition outputs into
// a durable activation intent. Restart recovery must call this again with
// freshly verified outputs and the same transition ID.
func ActivateResolvedProfile(ctx context.Context, controller *profileactivation.Controller,
	transitionID string, mode profileactivation.Mode,
	maxDrainDurationMS uint64,
	resolved profilecomposition.ValidatedResolvedProfile,
	inspection profilecomposition.ValidatedInspection,
	expectedActiveRevision uint64, expectedCompositionDigest string,
) (profileactivation.Result, error) {
	if err := profileCompositionContextError(ctx); err != nil {
		return profileactivation.Result{}, profileactivationError(err)
	}
	if controller == nil || resolved.Digest() == "" || inspection.Digest() == "" {
		return profileactivation.Result{}, profileactivation.NewInvalidInput("verified_profile_required")
	}
	profile := resolved.Value()
	view := inspection.Value()
	if profile.CompositionDigest != resolved.Digest() || view.InspectionDigest != inspection.Digest() ||
		view.ProfileID != profile.ProfileID || view.ProfileRevision != profile.Revision || view.Target != profile.Target ||
		view.ProfileBindingDigest != profile.ProfileBindingDigest || view.CompositionDigest != profile.CompositionDigest ||
		view.CapabilityGraphDigest != profile.CapabilityGraphDigest {
		return profileactivation.Result{}, profileactivation.NewDenied("inspection_binding")
	}
	target := profileactivation.Target{DeploymentKind: profile.Target.DeploymentKind,
		ConnectivityMode: profile.Target.ConnectivityMode, Platform: profile.Target.Platform, Surface: profile.Target.Surface}
	request := profileactivation.Request{TransitionID: transitionID, Mode: mode,
		MaxDrainDurationMS: maxDrainDurationMS,
		Candidate: profileactivation.Candidate{ProfileID: profile.ProfileID, ProfileRevision: profile.Revision,
			Target: target, ProfileBindingDigest: profile.ProfileBindingDigest,
			CompositionDigest: profile.CompositionDigest, CapabilityGraphDigest: profile.CapabilityGraphDigest,
			InspectionDigest: inspection.Digest()}, ExpectedActiveRevision: expectedActiveRevision,
		ExpectedCompositionDigest: expectedCompositionDigest}
	return controller.Activate(ctx, request)
}

func profileactivationError(err error) error {
	switch profilecomposition.Code(err) {
	case profilecomposition.Canceled:
		return profileactivation.NewCanceled(profilecomposition.Reason(err))
	case profilecomposition.Timeout:
		return profileactivation.NewTimeout(profilecomposition.Reason(err))
	default:
		return profileactivation.NewInvalidInput(profilecomposition.Reason(err))
	}
}
