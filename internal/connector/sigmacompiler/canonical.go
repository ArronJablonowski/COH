package sigmacompiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func SigmaDigest(value string) string { return digest("COH-SIGMA-SOURCE-V1\x00", value) }

func MappingDigest(value MappingBinding) string {
	value.MappingDigest = ""
	return digest("COH-SIGMA-MAPPING-V1\x00", value)
}

func PolicyDigest(value Policy) string { return digest("COH-SIGMA-POLICY-V1\x00", value) }

func CompileRequestDigest(value CompileRequest) string {
	value.RequestDigest = ""
	return digest("COH-SIGMA-COMPILE-REQUEST-V1\x00", value)
}

func NativeQueryDigest(value string) string { return digest("COH-SIGMA-NATIVE-QUERY-V1\x00", value) }

func CompileResponseDigest(value CompileResponse) string {
	value.ResponseDigest = ""
	return digest("COH-SIGMA-COMPILE-RESPONSE-V1\x00", value)
}

func CapabilitySnapshotDigest(value CapabilitySnapshot) string {
	value.Digest = ""
	return digest("COH-SIGMA-CAPABILITY-V1\x00", value)
}

func HelperAttestationDigest(value HelperAttestation) string {
	value.Digest = ""
	return digest("COH-SIGMA-ATTESTATION-V1\x00", value)
}

func ProvenanceReceiptDigest(value ProvenanceReceipt) string {
	value.Digest = ""
	return digest("COH-SIGMA-PROVENANCE-V1\x00", value)
}

func digest(domain string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(encoded)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
