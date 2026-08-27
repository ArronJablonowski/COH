package evidenceingest

import (
	"crypto/sha256"
	"encoding/hex"
)

func deterministicUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func contentDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
