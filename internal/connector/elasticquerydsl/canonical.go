package elasticquerydsl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func digest(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(domain), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
