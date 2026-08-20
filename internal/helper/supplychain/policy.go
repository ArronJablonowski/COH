package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const PolicySchema = "coh.release-policy/v1"

type Policy struct {
	SchemaVersion   string               `json:"schema_version"`
	ContractVersion string               `json:"contract_version"`
	ReleaseVersion  string               `json:"release_version"`
	BuilderIDs      []string             `json:"builder_ids"`
	Targets         []string             `json:"targets"`
	GoVersions      []string             `json:"go_versions"`
	ReleaseGoBins   []ReleaseGoBinary    `json:"release_go_binaries"`
	Archive         []ArchiveRequirement `json:"archive"`
	TrustedKeys     []PolicyKey          `json:"trusted_keys"`
}

type ReleaseGoBinary struct {
	GoVersion string `json:"go_version"`
	SHA256    string `json:"sha256"`
}

type PolicyKey struct {
	KeyID         string `json:"key_id"`
	Role          string `json:"role"`
	PublicKeyPath string `json:"public_key_path"`
}

func DecodePolicy(encoded []byte) (Policy, string, error) {
	var policy Policy
	if err := decodeStrict(encoded, &policy); err != nil {
		return Policy{}, "", errorf(CodeInvalidInput, "policy", "invalid release policy", err)
	}
	if err := validatePolicy(policy); err != nil {
		return Policy{}, "", err
	}
	canonical, err := json.Marshal(policy)
	if err != nil {
		return Policy{}, "", errorf(CodeToolFailure, "policy", "cannot canonicalize release policy", err)
	}
	digest := sha256.Sum256(canonical)
	return policy, hex.EncodeToString(digest[:]), nil
}

func ReadPolicy(path string) (Policy, string, error) {
	encoded, err := readStableRegular(path, 1<<20)
	if err != nil {
		return Policy{}, "", err
	}
	return DecodePolicy(encoded)
}

func LoadTrustedKey(root string, policy Policy, role string) (TrustedKey, error) {
	for _, key := range policy.TrustedKeys {
		if key.Role != role {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(key.PublicKeyPath))
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return TrustedKey{}, errorf(CodeDenied, "policy.trusted_keys", "public key escapes repository root", relErr)
		}
		encoded, err := readStableRegular(path, 1<<16)
		if err != nil {
			return TrustedKey{}, err
		}
		trusted := TrustedKey{KeyID: key.KeyID, Role: key.Role, PublicPEM: encoded}
		publicKey, err := parsePublicKey(encoded)
		if err != nil {
			return TrustedKey{}, err
		}
		if publicKeyID(publicKey) != key.KeyID {
			return TrustedKey{}, errorf(CodeDenied, "policy.trusted_keys", "public key digest differs from policy", nil)
		}
		return trusted, nil
	}
	return TrustedKey{}, errorf(CodeDenied, "policy.trusted_keys", "required signing role is not approved", os.ErrNotExist)
}

func validatePolicy(policy Policy) error {
	if policy.SchemaVersion != PolicySchema || policy.ContractVersion != ContractVersion ||
		!validVersion(policy.ReleaseVersion) || len(policy.BuilderIDs) != 2 || len(policy.Targets) == 0 ||
		len(policy.GoVersions) == 0 || len(policy.Archive) == 0 || len(policy.TrustedKeys) == 0 {
		return errorf(CodeDenied, "policy", "release policy is incomplete or unsupported", nil)
	}
	if len(policy.ReleaseGoBins) != len(policy.GoVersions) {
		return errorf(CodeDenied, "policy.release_go_binaries", "each approved Go version requires a release binary digest", nil)
	}
	for index, binary := range policy.ReleaseGoBins {
		if !validGoVersion(binary.GoVersion) || !validDigest(binary.SHA256) || binary.GoVersion != policy.GoVersions[index] ||
			(index > 0 && binary.GoVersion <= policy.ReleaseGoBins[index-1].GoVersion) {
			return errorf(CodeDenied, "policy.release_go_binaries", "release Go binary set is invalid or unordered", nil)
		}
	}
	if !slices.IsSorted(policy.BuilderIDs) || !slices.IsSorted(policy.Targets) || !slices.IsSorted(policy.GoVersions) {
		return errorf(CodeDenied, "policy", "targets and Go versions must be sorted", nil)
	}
	expectedBuilders := []string{
		"https://github.com/ArronJablonowski/COH/blob/main/docs/design/release-supply-chain.md#github-hosted-builder",
		"https://github.com/ArronJablonowski/COH/blob/main/docs/design/release-supply-chain.md#native-studio-builder",
	}
	expectedTargets := []string{"darwin/arm64", "linux/amd64", "linux/arm64"}
	expectedGoVersions := []string{"go1.26.7", "go1.27.0"}
	if !slices.Equal(policy.BuilderIDs, expectedBuilders) || !slices.Equal(policy.Targets, expectedTargets) || !slices.Equal(policy.GoVersions, expectedGoVersions) {
		return errorf(CodeDenied, "policy", "v1 builder, target, or Go version set differs", nil)
	}
	for index, builder := range policy.BuilderIDs {
		if !strings.HasPrefix(builder, "https://github.com/ArronJablonowski/COH/") ||
			(index > 0 && builder == policy.BuilderIDs[index-1]) {
			return errorf(CodeDenied, "policy.builder_ids", "builder identity set is invalid", nil)
		}
	}
	for index, target := range policy.Targets {
		if !validTarget(target) || (index > 0 && target == policy.Targets[index-1]) {
			return errorf(CodeDenied, "policy.targets", "target set is invalid", nil)
		}
	}
	for index, version := range policy.GoVersions {
		if !validGoVersion(version) || (index > 0 && version == policy.GoVersions[index-1]) {
			return errorf(CodeDenied, "policy.go_versions", "Go version set is invalid", nil)
		}
	}
	previous := ""
	expectedArchive := []ArchiveRequirement{
		{Path: "bin/archcheck", Mode: 0o555, Package: "github.com/ArronJablonowski/COH/cmd/archcheck"},
		{Path: "bin/installgate", Mode: 0o555, Package: "github.com/ArronJablonowski/COH/cmd/installgate"},
		{Path: "bin/qualitygate", Mode: 0o555, Package: "github.com/ArronJablonowski/COH/cmd/qualitygate"},
		{Path: "share/coh/LICENSE", Mode: 0o444},
		{Path: "share/coh/install_release.sh", Mode: 0o555},
		{Path: "share/coh/release-files.sha256", Mode: 0o444},
	}
	if !slices.Equal(policy.Archive, expectedArchive) {
		return errorf(CodeDenied, "policy.archive", "v1 archive contract differs", nil)
	}
	for _, entry := range policy.Archive {
		if !validArchivePath(entry.Path) || entry.Path <= previous || (entry.Mode != 0o444 && entry.Mode != 0o555) {
			return errorf(CodeDenied, "policy.archive", "archive contract is invalid or unordered", nil)
		}
		if strings.HasPrefix(entry.Path, "bin/") != (entry.Package != "") {
			return errorf(CodeDenied, "policy.archive", "binary package identity is missing or misplaced", nil)
		}
		previous = entry.Path
	}
	previous = ""
	for _, key := range policy.TrustedKeys {
		if key.KeyID <= previous || len(key.KeyID) != len("sha256:")+64 || !validDigest(key.KeyID[len("sha256:"):]) ||
			(key.Role != "release" && key.Role != "ci-fixture") || filepath.IsAbs(key.PublicKeyPath) ||
			filepath.Clean(key.PublicKeyPath) != filepath.FromSlash(key.PublicKeyPath) || key.PublicKeyPath == ".." ||
			strings.HasPrefix(key.PublicKeyPath, "../") {
			return errorf(CodeDenied, "policy.trusted_keys", "trusted key contract is invalid or unordered", nil)
		}
		previous = key.KeyID
	}
	if len(policy.TrustedKeys) != 2 || policy.TrustedKeys[0].Role != "release" || policy.TrustedKeys[1].Role != "ci-fixture" {
		return errorf(CodeDenied, "policy.trusted_keys", "v1 signing-role set differs", nil)
	}
	return nil
}

func ReleaseGoBinaryApproved(policy Policy, artifact Artifact, goVersion string) bool {
	for _, binary := range policy.ReleaseGoBins {
		if binary.GoVersion == goVersion {
			return artifact.SHA256 == binary.SHA256
		}
	}
	return false
}
