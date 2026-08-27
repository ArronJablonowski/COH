package evidencelifecycle

import (
	"bytes"
	"testing"
)

func TestStrictCanonicalManifestAndSignatureDecode(t *testing.T) {
	manifest := validExportManifest(t)
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExportManifest(canonical)
	if err != nil || decoded.ManifestDigest != manifest.ManifestDigest || decoded.Case != manifest.Case {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	signature := validDetachedSignature(manifest.ManifestDigest)
	signatureBytes, _ := CanonicalDetachedSignature(signature)
	decodedSignature, err := DecodeDetachedSignature(signatureBytes)
	if err != nil || decodedSignature != signature {
		t.Fatalf("decoded=%+v err=%v", decodedSignature, err)
	}
	for name, value := range map[string][]byte{
		"noncanonical": append([]byte(" "), canonical...),
		"trailing":     append(append([]byte(nil), canonical...), '\n'),
		"duplicate":    bytes.Replace(canonical, []byte(`{"actor_id":`), []byte(`{"actor_id":"`+lifecycleUUID("other")+`","actor_id":`), 1),
		"unknown":      bytes.Replace(canonical, []byte(`{"actor_id":`), []byte(`{"added":null,"actor_id":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExportManifest(value); err == nil {
				t.Fatal("invalid manifest decoded")
			}
		})
	}
}
