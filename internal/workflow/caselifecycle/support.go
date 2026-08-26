package caselifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func deterministicUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}
