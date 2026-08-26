package policy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

// FinalizeDecision computes the decision digest over COH-CJ-1 bytes with the
// digest field empty. This is the only supported policy-decision digest.
func FinalizeDecision(decision Decision) (Decision, error) {
	decision.DecisionDigest = ""
	canonical, err := CanonicalDecisionBytes(decision)
	if err != nil {
		return Decision{}, NewError(InvalidInput, "policy_decision_encoding")
	}
	sum := sha256.Sum256(canonical)
	decision.DecisionDigest = "sha256:" + hex.EncodeToString(sum[:])
	return decision, nil
}

// VerifyDecisionDigest returns the exact canonical decision bytes after
// constant-time verification of the embedded digest.
func VerifyDecisionDigest(decision Decision) ([]byte, error) {
	supplied := decision.DecisionDigest
	finalized, err := FinalizeDecision(decision)
	if err != nil || subtle.ConstantTimeCompare([]byte(supplied), []byte(finalized.DecisionDigest)) != 1 {
		return nil, NewError(Denied, "policy_decision_digest")
	}
	return CanonicalDecisionBytes(finalized)
}

func CanonicalDecisionBytes(decision Decision) ([]byte, error) {
	encoded, err := json.Marshal(decision)
	if err != nil {
		return nil, err
	}
	return domaincontract.Canonicalize(encoded)
}
