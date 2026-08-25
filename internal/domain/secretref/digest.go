package secretref

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func ReferenceDigest(reference Reference) (string, error) {
	if err := ValidateReference(reference); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(reference)
	if err != nil {
		return "", secretError(InvalidInput, "reference_encoding", nil)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
