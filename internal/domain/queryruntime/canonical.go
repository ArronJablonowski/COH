package queryruntime

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	sessionDigestDomain     = "COH-QUERY-RUNTIME-SESSION-V1\x00"
	slicePlanDigestDomain   = "COH-QUERY-SLICE-PLAN-V1\x00"
	sliceDigestDomain       = "COH-QUERY-SLICE-V1\x00"
	rateRequestDigestDomain = "COH-QUERY-RATE-KEY-V1\x00"
	rateReservationDomain   = "COH-QUERY-RATE-RESERVATION-V1\x00"
	handleDigestDomain      = "COH-QUERY-RUNTIME-HANDLE-V1\x00"
	cancellationDomain      = "COH-QUERY-CANCELLATION-INTENT-V1\x00"
	timestampLayout         = "2006-01-02T15:04:05.000000000Z"
)

func finalizeSession(value Session) (Session, error) {
	value.SessionDigest = ""
	if err := validateSession(value, true); err != nil {
		return Session{}, err
	}
	digest, err := canonicalDigest(sessionDigestDomain, value)
	if err != nil {
		return Session{}, err
	}
	value.SessionDigest = digest
	return value, nil
}

func VerifySession(value Session) error {
	supplied := value.SessionDigest
	value.SessionDigest = ""
	finalized, err := finalizeSession(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(supplied), []byte(finalized.SessionDigest)) != 1 {
		return newError(Conflict, "session_integrity", err)
	}
	return nil
}

func finalizeSlicePlan(value SlicePlan) (SlicePlan, error) {
	value.PlanDigest = ""
	if err := validateSlicePlan(value, true); err != nil {
		return SlicePlan{}, err
	}
	digest, err := canonicalDigest(slicePlanDigestDomain, value)
	if err != nil {
		return SlicePlan{}, err
	}
	value.PlanDigest = digest
	return value, nil
}

func VerifySlicePlan(value SlicePlan) error {
	supplied := value.PlanDigest
	value.PlanDigest = ""
	finalized, err := finalizeSlicePlan(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(supplied), []byte(finalized.PlanDigest)) != 1 {
		return newError(Conflict, "slice_plan_integrity", err)
	}
	return nil
}

// FinalizeRateReservation lets a RateGate produce the canonical reservation
// record that the controller independently verifies before adapter I/O.
func FinalizeRateReservation(value RateReservation) (RateReservation, error) {
	value.ReservationDigest = ""
	if err := validateRateReservation(value, true); err != nil {
		return RateReservation{}, err
	}
	digest, err := canonicalDigest(rateReservationDomain, value)
	if err != nil {
		return RateReservation{}, err
	}
	value.ReservationDigest = digest
	return value, nil
}

func VerifyRateReservation(value RateReservation) error {
	supplied := value.ReservationDigest
	value.ReservationDigest = ""
	finalized, err := FinalizeRateReservation(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(supplied), []byte(finalized.ReservationDigest)) != 1 {
		return newError(Conflict, "rate_reservation_integrity", err)
	}
	return nil
}

func canonicalDigest(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", newError(Internal, "canonicalization_failed", err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(Internal, "canonicalization_failed", err)
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
