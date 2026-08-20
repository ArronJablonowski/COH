package supplychain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

const ciFixtureKeyDomain = "COH CYB-37 PUBLIC CI FIXTURE KEY v1; NEVER AUTHORIZE RELEASES"

func CIFixtureKey() ([]byte, TrustedKey, error) {
	seed := sha256.Sum256([]byte(ciFixtureKeyDomain))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, TrustedKey{}, errorf(CodeToolFailure, "ci_fixture_key", "cannot encode fixture private key", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, TrustedKey{}, errorf(CodeToolFailure, "ci_fixture_key", "cannot encode fixture public key", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), TrustedKey{
		KeyID: publicKeyID(publicKey), Role: "ci-fixture",
		PublicPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
	}, nil
}
