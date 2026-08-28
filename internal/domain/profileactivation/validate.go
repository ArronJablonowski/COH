package profileactivation

import (
	"context"
	"regexp"
	"slices"
	"time"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	timePattern   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

func validateRequest(value Request) error {
	if !validUUID(value.TransitionID) || !validCandidate(value.Candidate) ||
		value.MaxDrainDurationMS < 1000 || value.MaxDrainDurationMS > 300000 ||
		value.ExpectedActiveRevision > uint64(1<<63-1) ||
		(value.ExpectedActiveRevision == 0) != (value.ExpectedCompositionDigest == "") ||
		value.ExpectedCompositionDigest != "" && !validDigest(value.ExpectedCompositionDigest) {
		return newError(InvalidInput, "activation_request")
	}
	if value.Mode == LiveReload {
		return newError(Denied, "live_hot_reload")
	}
	if value.Mode != Startup && value.Mode != Maintenance {
		return newError(InvalidInput, "activation_mode")
	}
	if value.Mode == Startup && value.ExpectedActiveRevision != 0 {
		return newError(Denied, "startup_replacement")
	}
	return nil
}

func validateTransition(value Transition, sealed bool) error {
	if value.SchemaVersion != TransitionSchema || value.ContractVersion != ContractVersion ||
		!validUUID(value.TransitionID) || !validDigest(value.IntentDigest) || !validCandidate(value.Candidate) ||
		value.ExpectedActiveRevision > uint64(1<<63-1) ||
		(value.ExpectedActiveRevision == 0) != (value.ExpectedCompositionDigest == "") ||
		value.ExpectedCompositionDigest != "" && !validDigest(value.ExpectedCompositionDigest) ||
		!slices.Contains([]Mode{Startup, Maintenance}, value.Mode) ||
		value.MaxDrainDurationMS < 1000 || value.MaxDrainDurationMS > 300000 ||
		!slices.Contains([]Phase{Prepared, Quiescent, Published, Active}, value.Phase) ||
		value.Sequence == 0 || value.Sequence > uint64(1<<63-1) || !validTime(value.CreatedAt) ||
		!validTime(value.UpdatedAt) || value.UpdatedAt < value.CreatedAt ||
		sealed != validDigest(value.TransitionDigest) {
		return newError(InvalidInput, "transition")
	}
	if value.Phase == Prepared && value.QuiescenceDigest != "" ||
		value.Phase != Prepared && !validDigest(value.QuiescenceDigest) {
		return newError(InvalidInput, "transition_phase")
	}
	return nil
}

func validateActive(value ActiveProfile, sealed bool) error {
	if value.SchemaVersion != ActiveProfileSchema || value.ContractVersion != ContractVersion ||
		!validUUID(value.ProfileID) || value.ProfileRevision == 0 || value.ProfileRevision > uint64(1<<63-1) ||
		!validTarget(value.Target) || !validDigest(value.ProfileBindingDigest) ||
		!validDigest(value.CompositionDigest) || !validDigest(value.CapabilityGraphDigest) ||
		!validDigest(value.InspectionDigest) || !validUUID(value.TransitionID) || !validTime(value.ActivatedAt) ||
		sealed != validDigest(value.ActiveDigest) {
		return newError(InvalidInput, "active_profile")
	}
	return nil
}

func validCandidate(value Candidate) bool {
	return validUUID(value.ProfileID) && value.ProfileRevision > 0 && value.ProfileRevision <= uint64(1<<63-1) &&
		validTarget(value.Target) && validDigest(value.ProfileBindingDigest) && validDigest(value.CompositionDigest) &&
		validDigest(value.CapabilityGraphDigest) && validDigest(value.InspectionDigest)
}

func validTarget(value Target) bool {
	return slices.Contains([]string{"compose", "native_server", "native_workstation"}, value.DeploymentKind) &&
		slices.Contains([]string{"air_gapped", "connected", "restricted_connected"}, value.ConnectivityMode) &&
		slices.Contains([]string{"darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64"}, value.Platform) &&
		slices.Contains([]string{"api", "cli", "headless", "test", "web"}, value.Surface)
}

func validAttestation(value QuiescenceAttestation, transitionID string) bool {
	return value.TransitionID == transitionID && validDigest(value.AttestationDigest) &&
		value.AdmissionsStopped && value.ActiveWork == 0 && value.Durable
}

func validTime(value string) bool {
	if !timePattern.MatchString(value) {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05Z", value)
	return err == nil
}
func formatTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
func validUUID(value string) bool   { return uuidPattern.MatchString(value) }
func validDigest(value string) bool { return digestPattern.MatchString(value) }

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_missing")
	}
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return newError(Timeout, "deadline_exceeded")
		}
		return newError(Canceled, "context_canceled")
	default:
		return nil
	}
}
