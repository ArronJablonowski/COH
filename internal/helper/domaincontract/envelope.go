package domaincontract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var (
	ErrCancelled = errors.New("domain contract cancelled")
	ErrTimeout   = errors.New("domain contract timed out")
	uuidV7       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	timestamp    = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9][.][0-9]{9}Z$`)
)

var registeredKinds = map[string]struct{}{
	"action": {}, "approval": {}, "artifact_manifest": {}, "case": {},
	"claim": {}, "evidence": {}, "finding": {}, "model": {}, "query": {},
	"risk": {}, "roe": {}, "run": {}, "skill": {}, "task": {},
	"timeline_event": {}, "vulnerability": {},
}

var envelopeFields = map[string]struct{}{
	"schema": {}, "kind": {}, "id": {}, "organization_id": {},
	"tenant_id": {}, "case_id": {}, "revision": {}, "created_at": {}, "data": {},
}

// ValidateEnvelope validates the strict v1 envelope and returns canonical bytes.
// Per-kind data validation is deliberately a separate phase.
func ValidateEnvelope(ctx context.Context, input []byte) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	decoded, err := DecodeUnique(input)
	if err != nil {
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, deny("top-level value must be an object")
	}
	if len(object) != len(envelopeFields) {
		return nil, deny("envelope field count")
	}
	for field := range object {
		if _, allowed := envelopeFields[field]; !allowed {
			return nil, deny("unknown envelope field %q", field)
		}
	}
	if object["schema"] != "coh.domain/v1" {
		return nil, deny("unsupported schema")
	}
	kind, ok := object["kind"].(string)
	if !ok {
		return nil, deny("kind type")
	}
	if _, registered := registeredKinds[kind]; !registered {
		return nil, deny("unregistered kind")
	}
	for _, field := range []string{"id", "organization_id", "tenant_id"} {
		if !validUUID(object[field]) {
			return nil, deny("%s must be UUIDv7", field)
		}
	}
	if object["case_id"] != nil && !validUUID(object["case_id"]) {
		return nil, deny("case_id must be UUIDv7 or null")
	}
	if !validRevision(object["revision"]) {
		return nil, deny("revision must be a positive int64")
	}
	if !validTimestamp(object["created_at"]) {
		return nil, deny("created_at must be canonical UTC nanoseconds")
	}
	data, ok := object["data"].(map[string]any)
	if !ok || len(data) > 128 {
		return nil, deny("data must be a bounded object")
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return Canonicalize(input)
}

func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		cause := context.Cause(ctx)
		if errors.Is(cause, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %v", ErrTimeout, cause)
		}
		return fmt.Errorf("%w: %v", ErrCancelled, cause)
	default:
		return nil
	}
}

func deny(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(format, values...))
}

func validUUID(value any) bool {
	text, ok := value.(string)
	return ok && uuidV7.MatchString(text)
}

func validRevision(value any) bool {
	number, ok := value.(json.Number)
	if !ok || !canonicalInteger(number.String()) || number.String()[0] == '-' {
		return false
	}
	revision, err := strconv.ParseInt(number.String(), 10, 64)
	return err == nil && revision >= 1
}

func validTimestamp(value any) bool {
	text, ok := value.(string)
	if !ok || !timestamp.MatchString(text) {
		return false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", text)
	return err == nil && parsed.Format("2006-01-02T15:04:05.000000000Z") == text
}
