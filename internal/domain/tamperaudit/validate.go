package tamperaudit

import (
	"encoding/base64"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	schemaPattern = regexp.MustCompile(`^coh\.[a-z][a-z0-9.-]*/v[1-9][0-9]*$`)
)

func ValidateEvent(event Event) error {
	if event.SchemaVersion != EventSchemaVersion || event.ContractVersion != ContractVersion {
		return ErrUnsupportedVersion
	}
	if !eventIdentity(event.EventID) || !uuidPattern.MatchString(event.OrganizationID) || !uuidPattern.MatchString(event.TenantID) {
		return ErrInvalidInput
	}
	for _, value := range []string{event.CaseID, event.ActorID, event.SubjectID} {
		if value != "" && !uuidPattern.MatchString(value) {
			return ErrInvalidInput
		}
	}
	if event.ActorID == "" && event.ActorRevision != 0 || event.ActorID != "" && event.ActorRevision == 0 ||
		event.SubjectID == "" && event.SubjectRevision != 0 {
		return ErrInvalidInput
	}
	if !schemaPattern.MatchString(event.SourceSchema) || !tokenPattern.MatchString(event.Operation) ||
		!tokenPattern.MatchString(event.Outcome) || !tokenPattern.MatchString(event.ReasonCode) {
		return ErrInvalidInput
	}
	if event.SubjectDigest != "" && !digestPattern.MatchString(event.SubjectDigest) || len(event.EvidenceDigests) > 32 {
		return ErrInvalidInput
	}
	if !slices.IsSorted(event.EvidenceDigests) || hasDuplicate(event.EvidenceDigests) {
		return ErrInvalidInput
	}
	for _, digest := range event.EvidenceDigests {
		if !digestPattern.MatchString(digest) {
			return ErrInvalidInput
		}
	}
	if event.OccurredAt != "" {
		if _, err := parseTime(event.OccurredAt); err != nil {
			return ErrInvalidInput
		}
	}
	return nil
}

func eventIdentity(value string) bool {
	return uuidPattern.MatchString(value) || digestPattern.MatchString(value)
}

// UUIDv7Time returns the canonical UTC millisecond encoded by a UUIDv7. It is
// used when a source decision has a stable request identity but no timestamp.
func UUIDv7Time(value string) (string, error) {
	if !uuidPattern.MatchString(value) {
		return "", ErrInvalidInput
	}
	hexMillis := strings.ReplaceAll(value[:13], "-", "")
	millis, err := strconv.ParseInt(hexMillis, 16, 64)
	if err != nil {
		return "", ErrInvalidInput
	}
	return time.UnixMilli(millis).UTC().Format(timestampLayout), nil
}

func ValidateRecord(record Record) error {
	if record.SchemaVersion != RecordSchemaVersion || record.ContractVersion != ContractVersion {
		return ErrUnsupportedVersion
	}
	if record.Sequence == 0 || record.OrganizationID != record.Event.OrganizationID || record.TenantID != record.Event.TenantID ||
		!digestPattern.MatchString(record.EventDigest) || !digestPattern.MatchString(record.PreviousChainHash) || !digestPattern.MatchString(record.ChainHash) {
		return ErrInvalidInput
	}
	if err := ValidateEvent(record.Event); err != nil {
		return err
	}
	appendedAt, err := parseTime(record.AppendedAt)
	if err != nil {
		return ErrInvalidInput
	}
	if record.Event.OccurredAt != "" {
		occurredAt, _ := parseTime(record.Event.OccurredAt)
		if appendedAt.Before(occurredAt) {
			return ErrInvalidInput
		}
	}
	return nil
}

func ValidateCheckpoint(checkpoint Checkpoint) error {
	if checkpoint.SchemaVersion != CheckpointSchemaVersion || checkpoint.ContractVersion != ContractVersion {
		return ErrUnsupportedVersion
	}
	if !uuidPattern.MatchString(checkpoint.CheckpointID) || !uuidPattern.MatchString(checkpoint.OrganizationID) ||
		!uuidPattern.MatchString(checkpoint.TenantID) || checkpoint.CoveredFromSequence == 0 || checkpoint.Sequence < checkpoint.CoveredFromSequence ||
		checkpoint.RecordCount != checkpoint.Sequence-checkpoint.CoveredFromSequence+1 || checkpoint.RecordCount > CheckpointRecordLimit ||
		!digestPattern.MatchString(checkpoint.ChainHash) {
		return ErrInvalidInput
	}
	if checkpoint.Reason != "daily" && checkpoint.Reason != "record_limit" && checkpoint.Reason != "manual_final" {
		return ErrInvalidInput
	}
	if !tokenPattern.MatchString(checkpoint.SigningKeyID) || checkpoint.SigningKeyRevision == 0 || checkpoint.SignatureAlgorithm != SignatureAlgorithm {
		return ErrInvalidInput
	}
	if _, err := parseTime(checkpoint.CreatedAt); err != nil {
		return ErrInvalidInput
	}
	signature, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != 64 || strings.Contains(checkpoint.Signature, "=") {
		return ErrInvalidInput
	}
	return nil
}

func parseTime(value string) (time.Time, error) { return time.Parse(timestampLayout, value) }

func hasDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}
