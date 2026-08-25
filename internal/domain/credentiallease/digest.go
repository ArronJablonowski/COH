package credentiallease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func RequestDigest(request IssuanceRequest) (string, error) {
	if err := ValidateIssuanceRequest(request); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", leaseError(InvalidInput, "issuance_encoding", nil)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
