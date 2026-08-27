package querybounds

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const decisionDigestDomain = "COH-QUERY-BOUND-DECISION-V1\x00"

func FinalizeDecision(decision Decision) (Decision, error) {
	decision.DecisionDigest = ""
	if err := validateDecision(decision); err != nil {
		return Decision{}, err
	}
	canonical, err := CanonicalDecision(decision)
	if err != nil {
		return Decision{}, newError(InvalidInput, "decision_encoding", err)
	}
	input := append([]byte(decisionDigestDomain), canonical...)
	sum := sha256.Sum256(input)
	decision.DecisionDigest = "sha256:" + hex.EncodeToString(sum[:])
	return decision, nil
}

func VerifyDecision(decision Decision) ([]byte, error) {
	supplied := decision.DecisionDigest
	finalized, err := FinalizeDecision(decision)
	if err != nil || subtle.ConstantTimeCompare([]byte(supplied), []byte(finalized.DecisionDigest)) != 1 {
		return nil, newError(Denied, "decision_digest", err)
	}
	return CanonicalDecision(finalized)
}

func CanonicalDecision(decision Decision) ([]byte, error) {
	encoded, err := json.Marshal(decision)
	if err != nil {
		return nil, err
	}
	return domaincontract.Canonicalize(encoded)
}
