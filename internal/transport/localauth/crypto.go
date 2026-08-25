package localauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

func signingMessage(id, organizationID, actorID, nonce string, expiresAt time.Time) []byte {
	return []byte(strings.Join([]string{
		"coh.local-auth.challenge/v1",
		id,
		organizationID,
		actorID,
		expiresAt.UTC().Format(time.RFC3339Nano),
		nonce,
	}, "\n"))
}

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func finalizeEvent(event AuthenticationEvent) AuthenticationEvent {
	event.EventDigest = ""
	encoded, err := json.Marshal(event)
	if err != nil {
		panic("local authentication event contains only JSON-safe fields")
	}
	sum := sha256.Sum256(encoded)
	event.EventDigest = "sha256:" + hex.EncodeToString(sum[:])
	return event
}

func encodeRaw(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
