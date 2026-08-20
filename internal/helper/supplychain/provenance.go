package supplychain

import (
	"encoding/json"
	"slices"
)

const (
	inTotoStatementType = "https://in-toto.io/Statement/v1"
	slsaPredicateType   = "https://slsa.dev/provenance/v1"
	releaseBuildType    = "https://coh.invalid/build-types/native-release/v1"
)

type SLSAStatement struct {
	Type          string        `json:"_type"`
	Subject       []SLSASubject `json:"subject"`
	PredicateType string        `json:"predicateType"`
	Predicate     SLSAPredicate `json:"predicate"`
}

type SLSASubject struct {
	Name   string     `json:"name"`
	Digest SLSADigest `json:"digest"`
}

type SLSADigest struct {
	SHA256    string `json:"sha256,omitempty"`
	GitCommit string `json:"gitCommit,omitempty"`
}

type SLSAPredicate struct {
	BuildDefinition SLSABuildDefinition `json:"buildDefinition"`
	RunDetails      SLSARunDetails      `json:"runDetails"`
}

type SLSABuildDefinition struct {
	BuildType            string                   `json:"buildType"`
	ExternalParameters   SLSAExternalParameters   `json:"externalParameters"`
	InternalParameters   SLSAInternalParameters   `json:"internalParameters"`
	ResolvedDependencies []SLSAResourceDescriptor `json:"resolvedDependencies"`
}

type SLSAExternalParameters struct {
	Version    string `json:"version"`
	Target     string `json:"target"`
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
}

type SLSAInternalParameters struct {
	Issue        string   `json:"issue"`
	Requirements []string `json:"requirements"`
}

type SLSAResourceDescriptor struct {
	URI    string     `json:"uri"`
	Digest SLSADigest `json:"digest"`
}

type SLSARunDetails struct {
	Builder SLSABuilder `json:"builder"`
}

type SLSABuilder struct {
	ID string `json:"id"`
}

func GenerateSLSAProvenance(archive, source, toolchain, policy Artifact, version, target, goVersion, builderID, revision string) ([]byte, error) {
	if filepathBaseInvalid(archive.Path) || !validDigest(archive.SHA256) ||
		!validDigest(source.SHA256) || !validDigest(toolchain.SHA256) || !validDigest(policy.SHA256) || !validVersion(version) ||
		!validTarget(target) || !validGoVersion(goVersion) || builderID == "" || !validRevision(revision) {
		return nil, errorf(CodeInvalidInput, "provenance", "release provenance inputs are invalid", nil)
	}
	statement := SLSAStatement{
		Type:          inTotoStatementType,
		Subject:       []SLSASubject{{Name: archive.Path, Digest: SLSADigest{SHA256: archive.SHA256}}},
		PredicateType: slsaPredicateType,
		Predicate: SLSAPredicate{
			BuildDefinition: SLSABuildDefinition{
				BuildType: releaseBuildType,
				ExternalParameters: SLSAExternalParameters{
					Version: version, Target: target,
					Repository: "https://github.com/ArronJablonowski/COH", Revision: revision,
				},
				InternalParameters: SLSAInternalParameters{Issue: releaseIssue, Requirements: slices.Clone(releaseRequirements)},
				ResolvedDependencies: []SLSAResourceDescriptor{
					{URI: "git+https://github.com/ArronJablonowski/COH@" + revision, Digest: SLSADigest{SHA256: source.SHA256, GitCommit: revision}},
					{URI: "pkg:golang/toolchain@" + goVersion, Digest: SLSADigest{SHA256: toolchain.SHA256}},
					{URI: "https://coh.invalid/policy/release/v1", Digest: SLSADigest{SHA256: policy.SHA256}},
				},
			},
			RunDetails: SLSARunDetails{Builder: SLSABuilder{ID: builderID}},
		},
	}
	encoded, err := json.Marshal(statement)
	if err != nil {
		return nil, errorf(CodeToolFailure, "provenance", "cannot encode SLSA statement", err)
	}
	return append(encoded, '\n'), nil
}

func VerifySLSAProvenance(encoded []byte, archive, source, toolchain, policy Artifact, version, target, goVersion, builderID, revision string) error {
	expected, err := GenerateSLSAProvenance(archive, source, toolchain, policy, version, target, goVersion, builderID, revision)
	if err != nil {
		return err
	}
	var statement SLSAStatement
	if err := decodeStrict(encoded, &statement); err != nil {
		return errorf(CodeInvalidInput, "provenance", "invalid in-toto statement", err)
	}
	if !slices.Equal(encoded, expected) {
		return errorf(CodeDenied, "provenance", "SLSA statement differs from canonical release inputs", nil)
	}
	return nil
}

func validGoVersion(value string) bool {
	return len(value) >= 5 && len(value) <= 32 && value[:2] == "go" && validVersion("v"+value[2:])
}

func validRevision(value string) bool {
	return (len(value) == 40 || len(value) == 64) && validHex(value)
}

func validHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
