package approvalfingerprint

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/policy"
)

const maximumInputBytes = 16 << 10

func Decode(ctx context.Context, input []byte) (Fingerprint, error) {
	if err := contextError(ctx); err != nil {
		return Fingerprint{}, err
	}
	if len(input) == 0 || len(input) > maximumInputBytes {
		return Fingerprint{}, policy.NewError(policy.InvalidInput, "fingerprint_contract")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return Fingerprint{}, policy.NewError(policy.InvalidInput, "fingerprint_contract")
	}
	var fingerprint Fingerprint
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fingerprint); err != nil {
		return Fingerprint{}, policy.NewError(policy.InvalidInput, "fingerprint_contract")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Fingerprint{}, policy.NewError(policy.InvalidInput, "fingerprint_contract")
	}
	if err := validateFingerprint(fingerprint); err != nil {
		return Fingerprint{}, err
	}
	fingerprint.ROEDigest = cloneString(fingerprint.ROEDigest)
	return fingerprint, nil
}

func validateFingerprint(value Fingerprint) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion ||
		!digestPattern.MatchString(value.FingerprintDigest) ||
		!digestPattern.MatchString(value.ManifestDigest) ||
		!digestPattern.MatchString(value.PolicyDecisionDigest) ||
		!uuidPattern.MatchString(value.OrganizationID) || !uuidPattern.MatchString(value.TenantID) ||
		!uuidPattern.MatchString(value.CaseID) || !uuidPattern.MatchString(value.RequestorActorID) ||
		!uuidPattern.MatchString(value.ActionOwnerActorID) || !digestPattern.MatchString(value.PolicyDigest) ||
		value.PolicyRevision == 0 || (value.ROEDigest != nil && !digestPattern.MatchString(*value.ROEDigest)) ||
		value.MaximumUseCount == 0 || value.MaximumUseCount > 1000 {
		return policy.NewError(policy.InvalidInput, "fingerprint_contract")
	}
	from, fromErr := time.Parse(timestampLayout, value.ValidFrom)
	until, untilErr := time.Parse(timestampLayout, value.ValidUntil)
	if fromErr != nil || untilErr != nil || !until.After(from) {
		return policy.NewError(policy.InvalidInput, "fingerprint_contract")
	}
	return nil
}
