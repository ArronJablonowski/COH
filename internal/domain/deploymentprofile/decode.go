package deploymentprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

// evaluate parses and validates one bounded profile and returns a redacted,
// digest-bound decision for both accepted and semantically denied inputs.
func evaluate(ctx context.Context, input []byte) (Decision, error) {
	if err := contextError(ctx); err != nil {
		return canceledDecision(err), err
	}
	if len(input) == 0 || len(input) > MaximumBytes {
		err := validationError(InvalidInput, "input_size", nil)
		return invalidDecision("input_size"), err
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		err = validationError(InvalidInput, "malformed_json", nil)
		return invalidDecision("malformed_json"), err
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		err = validationError(InvalidInput, "schema_shape", nil)
		return invalidDecision("schema_shape"), err
	}
	if err := requireEOF(decoder); err != nil {
		return invalidDecision("trailing_data"), err
	}
	if err := contextError(ctx); err != nil {
		return canceledDecision(err), err
	}
	configDigest := digestBytes(canonical)
	if config.SchemaVersion != SchemaVersion || config.ContractVersion != ContractVersion {
		decision := newDecision(config, configDigest, "invalid", "unsupported_contract")
		return decision, validationError(InvalidInput, "unsupported_contract", nil)
	}
	reason := validate(config)
	if reason != "" {
		decision := newDecision(config, configDigest, "denied", reason)
		return decision, validationError(Denied, reason, nil)
	}
	return newDecision(config, configDigest, "allowed", "profile_valid"), nil
}

func requireEOF(decoder *json.Decoder) error {
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return validationError(InvalidInput, "trailing_data", nil)
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return validationError(InvalidInput, "context_required", nil)
	}
	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return validationError(Timeout, "context_deadline", err)
		}
		return validationError(Canceled, "context_canceled", err)
	}
	return nil
}
