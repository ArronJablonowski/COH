package supplychain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestSignAndVerifyFile(t *testing.T) {
	privatePEM, publicPEM, keyID := testKey(t)
	directory := t.TempDir()
	input := filepath.Join(directory, "checksums.txt")
	if err := os.WriteFile(input, []byte("abc  artifact.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signature, err := SignFile(context.Background(), input, "checksums.txt", privatePEM, "release")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	trusted := TrustedKey{KeyID: keyID, Role: "release", PublicPEM: publicPEM}
	if err := VerifyFile(context.Background(), input, "checksums.txt", encoded, trusted); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(context.Background(), input, "checksums.txt", encoded, trusted); CodeOf(err) != CodeDenied {
		t.Fatalf("tampered subject code=%q err=%v", CodeOf(err), err)
	}
}

func TestVerifyRejectsUnknownFieldsAuthorityAndSignature(t *testing.T) {
	privatePEM, publicPEM, keyID := testKey(t)
	input := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(input, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signature, err := SignFile(context.Background(), input, "sbom.json", privatePEM, "release")
	if err != nil {
		t.Fatal(err)
	}
	trusted := TrustedKey{KeyID: keyID, Role: "release", PublicPEM: publicPEM}
	tests := []struct {
		name   string
		mutate func(map[string]any)
		code   ErrorCode
	}{
		{name: "unknown field", mutate: func(value map[string]any) { value["extra"] = true }, code: CodeInvalidInput},
		{name: "wrong role", mutate: func(value map[string]any) { value["role"] = "ci-fixture" }, code: CodeDenied},
		{name: "bad signature", mutate: func(value map[string]any) {
			value["signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
		}, code: CodeDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(signature)
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err := json.Unmarshal(encoded, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			encoded, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyFile(context.Background(), input, "sbom.json", encoded, trusted); CodeOf(err) != test.code {
				t.Fatalf("code=%q err=%v", CodeOf(err), err)
			}
		})
	}
}

func TestSignAndVerifyCancellationAndSymlinkDenial(t *testing.T) {
	privatePEM, publicPEM, keyID := testKey(t)
	directory := t.TempDir()
	realPath := filepath.Join(directory, "real")
	linkPath := filepath.Join(directory, "link")
	if err := os.WriteFile(realPath, []byte("subject"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := SignFile(context.Background(), linkPath, "subject", privatePEM, "release"); CodeOf(err) != CodeDenied {
		t.Fatalf("symlink code=%q err=%v", CodeOf(err), err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SignFile(canceled, realPath, "subject", privatePEM, "release"); CodeOf(err) != CodeCanceled {
		t.Fatalf("canceled sign code=%q err=%v", CodeOf(err), err)
	}
	trusted := TrustedKey{KeyID: keyID, Role: "release", PublicPEM: publicPEM}
	if err := VerifyFile(canceled, realPath, "subject", []byte("{}"), trusted); CodeOf(err) != CodeCanceled {
		t.Fatalf("canceled verify code=%q err=%v", CodeOf(err), err)
	}
}

func testKey(t *testing.T) ([]byte, []byte, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), publicKeyID(publicKey)
}

func TestCIFixtureKeyIsStableAndRoleBound(t *testing.T) {
	privatePEM, trusted, err := CIFixtureKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(privatePEM) == 0 || trusted.Role != "ci-fixture" ||
		trusted.KeyID != "sha256:c2d6aa555b261eb83958b61c1353dc04531721430bd6bb68d13ff4fc88f6e035" {
		t.Fatal("fixture key is incomplete")
	}
}

func TestPrivateKeyAuthorityRejectsWrongRoleAndKey(t *testing.T) {
	privatePEM, publicPEM, keyID := testKey(t)
	trusted := TrustedKey{KeyID: keyID, Role: "release", PublicPEM: publicPEM}
	if err := VerifyPrivateKeyAuthority(privatePEM, trusted); err != nil {
		t.Fatal(err)
	}
	_, fixture, err := CIFixtureKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivateKeyAuthority(privatePEM, fixture); CodeOf(err) != CodeDenied {
		t.Fatalf("wrong role code=%q err=%v", CodeOf(err), err)
	}
	otherPrivate, _, _ := testKey(t)
	if err := VerifyPrivateKeyAuthority(otherPrivate, trusted); CodeOf(err) != CodeDenied {
		t.Fatalf("wrong key code=%q err=%v", CodeOf(err), err)
	}
}
