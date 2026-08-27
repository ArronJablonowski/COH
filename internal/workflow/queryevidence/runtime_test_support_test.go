package queryevidence

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func canonicalRuntime(encoded []byte) (string, error) {
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("COH-QUERY-RUNTIME-SESSION-V1\x00"), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
