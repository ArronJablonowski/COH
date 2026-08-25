package oidcauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func encodeRaw(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func finalizeEvent(event Event) Event {
	event.EventDigest = ""
	encoded, err := json.Marshal(event)
	if err != nil {
		panic("OIDC event contains only JSON-safe fields")
	}
	sum := sha256.Sum256(encoded)
	event.EventDigest = "sha256:" + hex.EncodeToString(sum[:])
	return event
}
