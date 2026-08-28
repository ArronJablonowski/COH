package splunk

import (
	"encoding/json"
	"regexp"
	"slices"
	"time"
)

var progressPattern = regexp.MustCompile(`^(0(?:\.[0-9]{1,5})?|1(?:\.0{1,5})?)$`)

var lifecycleOperations = []string{
	"splunk.search.cancel", "splunk.search.create", "splunk.search.results", "splunk.search.status",
}

var lifecycleStates = []string{
	"BAD_INPUT_CANCEL", "DONE", "FAILED", "FINALIZING", "INTERNAL_CANCEL", "PARSING", "PAUSE", "QUEUED", "QUIT", "RUNNING", "USER_CANCEL",
}

func DecodeLifecyclePolicy(input []byte) (LifecyclePolicy, error) {
	var value LifecyclePolicy
	if err := decodeExact(input, &value); err != nil {
		return LifecyclePolicy{}, err
	}
	if value.SchemaVersion != LifecyclePolicyVersion || value.ContractVersion != ContractVersion ||
		value.ExecutionMode != "normal" || value.AllowPreviews || value.StatusBuckets != 0 ||
		value.MaximumPageRows != maximumSearchPageRows ||
		value.MinimumPollIntervalMillis != uint64(minimumSplunkPollInterval/time.Millisecond) ||
		value.CancellationWaitMillis != uint64(splunkCancellationWait/time.Millisecond) ||
		!slices.Equal(value.Operations, lifecycleOperations) || !slices.Equal(value.AllowedStates, lifecycleStates) {
		return LifecyclePolicy{}, denied("lifecycle policy invalid")
	}
	return value, nil
}

func DecodeSIDOwnership(input []byte) (SIDOwnership, error) {
	var value SIDOwnership
	if err := decodeExact(input, &value); err != nil {
		return SIDOwnership{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, value.ExpiresAt)
	if value.SchemaVersion != SIDOwnershipVersion || value.ContractVersion != ContractVersion ||
		!namePattern.MatchString(value.SourceID) || !validDigests(value.QueryDigest, value.PlanDigest, value.SIDDigest, value.OpaqueHandleDigest) ||
		err != nil || expiresAt.IsZero() || value.SIDExposed {
		return SIDOwnership{}, denied("SID ownership invalid")
	}
	return value, nil
}

func DecodeJobStatus(input []byte) (JobStatus, error) {
	var value JobStatus
	if err := decodeExact(input, &value); err != nil {
		return JobStatus{}, err
	}
	if value.SchemaVersion != JobStatusVersion || value.ContractVersion != ContractVersion ||
		!slices.Contains(lifecycleStates, value.State) || !progressPattern.MatchString(value.DoneProgress) ||
		value.Finalized || value.RealTime || value.Zombie || value.EventCount > value.ScanCount || value.ResultCount > value.EventCount ||
		!consistentJobFlags(value) {
		return JobStatus{}, denied("job status invalid")
	}
	return value, nil
}

func DecodeResultEnvelope(input []byte) (ResultEnvelope, error) {
	var value ResultEnvelope
	if err := decodeExact(input, &value); err != nil {
		return ResultEnvelope{}, err
	}
	if value.SchemaVersion != ResultEnvelopeVersion || value.ContractVersion != ContractVersion ||
		value.Count < 1 || value.Count > maximumSearchPageRows || uint64(len(value.Results)) > uint64(value.Count) ||
		value.Offset > value.Total || uint64(len(value.Results)) > value.Total-value.Offset ||
		!validResultFields(value.Fields) || len(value.Messages) > 16 || value.Truncated || !digestPattern.MatchString(value.ResultDigest) {
		return ResultEnvelope{}, denied("result envelope invalid")
	}
	allowed := make(map[string]struct{}, len(value.Fields))
	for _, field := range value.Fields {
		allowed[field] = struct{}{}
	}
	for _, row := range value.Results {
		if len(row) == 0 || len(row) > len(allowed) {
			return ResultEnvelope{}, denied("result row invalid")
		}
		for field, cell := range row {
			if _, ok := allowed[field]; !ok || len(cell) > 65536 {
				return ResultEnvelope{}, denied("result row invalid")
			}
		}
	}
	for _, message := range value.Messages {
		if !namePattern.MatchString(message) {
			return ResultEnvelope{}, denied("result message invalid")
		}
	}
	return value, nil
}

func DecodeCancellationProof(input []byte) (CancellationProof, error) {
	var value CancellationProof
	if err := decodeExact(input, &value); err != nil {
		return CancellationProof{}, err
	}
	requested, requestErr := time.Parse(time.RFC3339Nano, value.RequestedAt)
	confirmedValid := value.ConfirmedAt == nil
	if value.ConfirmedAt != nil {
		confirmed, err := time.Parse(time.RFC3339Nano, *value.ConfirmedAt)
		confirmedValid = err == nil && !confirmed.Before(requested)
	}
	if value.SchemaVersion != CancellationProofVersion || value.ContractVersion != ContractVersion ||
		!slices.Contains([]string{"confirmed", "uncertain"}, value.Outcome) || !namePattern.MatchString(value.ReasonCode) ||
		requestErr != nil || !confirmedValid || (value.Outcome == "confirmed") != (value.ConfirmedAt != nil) ||
		!validDigests(value.RequestDigest, value.ResponseDigest) || value.SIDExposed {
		return CancellationProof{}, denied("cancellation proof invalid")
	}
	return value, nil
}

func DecodeLifecycleDenialCorpus(input []byte) (DenialCorpus, error) {
	var value DenialCorpus
	if err := decodeExact(input, &value); err != nil {
		return DenialCorpus{}, err
	}
	if value.SchemaVersion != LifecycleDenialCorpusVersion {
		return DenialCorpus{}, denied("lifecycle denial corpus identity invalid")
	}
	encoded, _ := json.Marshal(DenialCorpus{SchemaVersion: DenialCorpusVersion, ContractVersion: value.ContractVersion, Cases: value.Cases})
	if _, err := DecodeDenialCorpus(encoded); err != nil {
		return DenialCorpus{}, err
	}
	return value, nil
}

func DecodeLifecycleRedactedError(input []byte) (RedactedError, error) {
	var value RedactedError
	if err := decodeExact(input, &value); err != nil {
		return RedactedError{}, err
	}
	if value.SchemaVersion != LifecycleRedactedErrorVersion {
		return RedactedError{}, denied("lifecycle redacted error identity invalid")
	}
	encoded, _ := json.Marshal(RedactedError{
		SchemaVersion: RedactedErrorVersion, ContractVersion: value.ContractVersion, Event: value.Event,
		ReasonCode: value.ReasonCode, SourceID: value.SourceID, RequestDigest: value.RequestDigest,
		ResponseDigest: value.ResponseDigest, LeaseDecisionDigest: value.LeaseDecisionDigest,
		TransportIdentityDigest: value.TransportIdentityDigest, CredentialExposed: value.CredentialExposed,
		BearerExposed: value.BearerExposed, SIDExposed: value.SIDExposed, NativeTextExposed: value.NativeTextExposed,
		ResultRowExposed: value.ResultRowExposed, VendorBodyExposed: value.VendorBodyExposed,
	})
	if _, err := DecodeRedactedError(encoded); err != nil {
		return RedactedError{}, err
	}
	return value, nil
}

func consistentJobFlags(value JobStatus) bool {
	terminalCancel := slices.Contains([]string{"BAD_INPUT_CANCEL", "INTERNAL_CANCEL", "USER_CANCEL", "QUIT"}, value.State)
	switch value.State {
	case "DONE":
		return value.Done && !value.Failed && value.DoneProgress == "1.00000"
	case "FAILED":
		return value.Done && value.Failed && !value.Finalized
	default:
		return terminalCancel == value.Done && !value.Failed && !value.Finalized
	}
}

func validResultFields(fields []string) bool {
	if len(fields) == 0 || len(fields) > 256 || !slices.IsSorted(fields) {
		return false
	}
	for index, field := range fields {
		if !namePattern.MatchString(field) || (index > 0 && field == fields[index-1]) {
			return false
		}
	}
	return true
}
