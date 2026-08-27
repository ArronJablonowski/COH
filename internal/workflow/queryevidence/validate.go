package queryevidence

import (
	"regexp"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$`)
)

func validDigest(value string) bool         { return digestPattern.MatchString(value) }
func validOptionalDigest(value string) bool { return value == "" || validDigest(value) }
func validTimestamp(value string) bool {
	parsed, err := time.Parse(timestampLayout, value)
	return err == nil && parsed.Format(timestampLayout) == value
}
func oneOf(value string, values ...string) bool { return slices.Contains(values, value) }
func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID)
}
func validCaseBinding(value CaseBinding) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID)
}
func validStream(value StreamRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID) && uuidPattern.MatchString(value.QueryID) && uuidPattern.MatchString(value.AttemptID)
}

func validArtifact(value ArtifactBinding) bool {
	return validDigest(value.Artifact.Digest) && value.Artifact.Length >= 0 && tokenPattern.MatchString(value.Artifact.Classification) &&
		len(value.Artifact.MediaType) > 0 && len(value.Artifact.MediaType) <= 255 && validDigest(value.Manifest.Digest) &&
		value.Manifest.Length >= 0 && tokenPattern.MatchString(value.Manifest.Classification) && len(value.Manifest.MediaType) > 0 &&
		value.Manifest.Classification == value.Artifact.Classification &&
		value.Manifest.MediaType == "application/vnd.coh.artifact-manifest+json" &&
		validDigest(value.ManifestProvenanceDigest) && validDigest(value.IngestionReceiptDigest)
}

func validateRecord(value Record, digestsEmpty bool) error {
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion ||
		(digestsEmpty && (value.RecordDigest != "" || value.ProvenanceDigest != "" || value.TransitionID != "")) ||
		(!digestsEmpty && (!validDigest(value.RecordDigest) || !validDigest(value.ProvenanceDigest) || !validDigest(value.TransitionID))) ||
		value.Revision == 0 || !validStream(value.Stream) || !validCaseBinding(value.Case) ||
		value.Stream.OrganizationID != value.Case.OrganizationID || value.Stream.TenantID != value.Case.TenantID || value.Stream.CaseID != value.Case.CaseID ||
		!uuidPattern.MatchString(value.ActorID) || !tokenPattern.MatchString(value.SourceID) || !validDigest(value.QueryDigest) ||
		!validDigest(value.BoundsDecisionDigest) || !validDigest(value.ExecutionDigest) || !versionPattern.MatchString(value.ValidatorVersion) ||
		!validDigest(value.ValidatorProvenanceDigest) || !validTimestamp(value.IntervalStart) || !validTimestamp(value.IntervalEnd) ||
		!validDigest(value.ResourceScopeDigest) || !validArtifact(value.NativeQuery) ||
		!oneOf(value.Event, "started", "validated", "page", "result", "truncated", "partial", "cancellation_requested", "canceled", "uncertain", "failed") ||
		value.RuntimeSessionRevision == 0 || !validDigest(value.RuntimeSessionDigest) ||
		!oneOf(value.Completeness, "running", "complete", "partial", "truncated", "canceled", "uncertain", "failed") ||
		!tokenPattern.MatchString(value.ReasonCode) || !validOptionalDigest(value.ResultDigest) ||
		!validOptionalDigest(value.CancellationIntentDigest) || !validOptionalDigest(value.CancellationOutcomeDigest) || !validTimestamp(value.OccurredAt) {
		return newError(InvalidInput, "record_invalid", nil)
	}
	start, _ := time.Parse(timestampLayout, value.IntervalStart)
	end, _ := time.Parse(timestampLayout, value.IntervalEnd)
	if !start.Before(end) || (value.Revision == 1) != (value.PreviousProvenanceDigest == "") ||
		(value.Revision > 1 && !validDigest(value.PreviousProvenanceDigest)) || value.Statistics.RowsReturned > value.Statistics.RowsScanned ||
		(value.Result != nil && (!validArtifact(*value.Result) || value.Result.Artifact.Digest != value.ResultDigest)) ||
		(value.Event == "started" && (value.Revision != 1 || value.Completeness != "running")) ||
		(value.Event == "cancellation_requested" && value.CancellationIntentDigest == "") ||
		(value.Event == "canceled" && (value.CancellationIntentDigest == "" || value.CancellationOutcomeDigest == "" || value.Completeness != "canceled")) {
		return newError(InvalidInput, "record_invalid", nil)
	}
	return nil
}

func validateAudit(value AuditEvent, digestEmpty bool) error {
	if value.SchemaVersion != AuditSchemaVersion || value.ContractVersion != ContractVersion ||
		(digestEmpty && value.EventDigest != "") || (!digestEmpty && !validDigest(value.EventDigest)) ||
		!validDigest(value.TransitionID) || !validDigest(value.RecordDigest) || !validDigest(value.ProvenanceDigest) ||
		!validStream(value.Stream) || value.Revision == 0 || !tokenPattern.MatchString(value.Event) ||
		!oneOf(value.Outcome, "committed", "replayed") || !validTimestamp(value.OccurredAt) {
		return newError(InvalidInput, "audit_event_invalid", nil)
	}
	return nil
}
