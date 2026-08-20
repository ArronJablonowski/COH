package supplychain

import (
	"crypto/sha256"
	"fmt"
)

func deterministicUUID(input []byte) string {
	sum := sha256.Sum256(input)
	value := sum[:16]
	value[6] = (value[6] & 0x0f) | 0x50
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}
