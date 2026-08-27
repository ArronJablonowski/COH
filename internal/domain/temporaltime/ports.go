package temporaltime

import (
	"context"
	"time"
)

// EvidenceVerifier verifies identities only. It cannot return evidence bytes,
// vendor fields, storage locations, credentials, or policy source.
type EvidenceVerifier interface {
	VerifyBinding(context.Context, Case, SourceBinding) error
}

// Parser interprets one explicitly selected format into location-free civil
// components. Timezone selection is a separate boundary.
type Parser interface {
	Parse(context.Context, string, string, Precision) (CivilTime, error)
}

type ParserRegistry interface {
	ResolveParser(context.Context, ParserIdentity) (Parser, error)
}

// TimezoneResolver must use the exact assertion and tzdata identity supplied
// by the command. It returns zero, one, or two conservative civil intervals.
type TimezoneResolver interface {
	ResolveCivil(context.Context, CivilTime, TimezoneAssertion) (TimezoneResolution, error)
}

// CalibrationResolver verifies that a calibration identity and its signed
// estimate still match durable case state; it cannot mint a new calibration.
type CalibrationResolver interface {
	ResolveCalibration(context.Context, Case, Calibration) (Calibration, error)
}

// RecordStore owns the idempotency boundary. Commit atomically persists the
// exact command, record, receipt, audit record, and provenance link.
type RecordStore interface {
	LoadReceipt(context.Context, string) (Receipt, bool, error)
	LoadCommandDigest(context.Context, string) (string, bool, error)
	Begin(context.Context, Command, string) (bool, error)
	Commit(context.Context, Commit) error
	CommitComparison(context.Context, ComparisonCommit) error
}

// AuditBuilder creates a data-only audit record for atomic persistence by the
// store. Closed codes prevent source text from leaking into audit messages.
type AuditBuilder interface {
	BuildAudit(context.Context, string, string, Outcome, Reason) (AuditRecord, error)
	BuildComparisonAudit(context.Context, Comparison) (string, error)
}

type ProvenanceBuilder interface {
	BuildProvenance(context.Context, string, string, string) (ProvenanceRecord, error)
	BuildComparisonProvenance(context.Context, Comparison, string) (string, string, error)
}

type Clock interface {
	Now() time.Time
}

// Dependencies is explicit to keep the service boundary reviewable. It has no
// shell, HTTP, SQL, path, connector, executor, credential, or callback field.
type Dependencies struct {
	Evidence     EvidenceVerifier
	Parsers      ParserRegistry
	Timezones    TimezoneResolver
	Calibrations CalibrationResolver
	Store        RecordStore
	Audit        AuditBuilder
	Provenance   ProvenanceBuilder
	Clock        Clock
}
