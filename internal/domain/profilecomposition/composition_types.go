package profilecomposition

import (
	"encoding/json"
)

const (
	ResolvedProfileSchemaVersion = "coh.resolved-profile/v1"
	profileBindingDomain         = "COH-PROFILE-BINDING-V1\x00"
	resolvedProfileDomain        = "COH-RESOLVED-PROFILE-V1\x00"
	signatureSetDomain           = "COH-PROFILE-SIGNATURE-SET-V1\x00"
)

type ExactTarget struct {
	DeploymentKind   string `json:"deployment_kind"`
	ConnectivityMode string `json:"connectivity_mode"`
	Platform         string `json:"platform"`
	Surface          string `json:"surface"`
}

type Request struct {
	ProfileID string
	Revision  uint64
	Target    ExactTarget
}

type LayerBinding struct {
	LayerID                     string `json:"layer_id"`
	Name                        string `json:"name"`
	Kind                        string `json:"kind"`
	Revision                    uint64 `json:"revision"`
	Precedence                  uint64 `json:"precedence"`
	LayerDigest                 string `json:"layer_digest"`
	PredecessorDigest           string `json:"predecessor_digest"`
	SignatureSetDigest          string `json:"signature_set_digest"`
	PublisherKeyRevision        uint64 `json:"publisher_key_revision"`
	TrustRevision               uint64 `json:"trust_revision"`
	RevocationRevision          uint64 `json:"revocation_revision"`
	RollbackAuthorizationDigest string `json:"rollback_authorization_digest"`
}

type ResolvedProfile struct {
	SchemaVersion         string         `json:"schema_version"`
	ContractVersion       string         `json:"contract_version"`
	ProfileID             string         `json:"profile_id"`
	Revision              uint64         `json:"revision"`
	Target                ExactTarget    `json:"target"`
	OrderedLayers         []LayerBinding `json:"ordered_layers"`
	DeploymentProfile     ArtifactRef    `json:"deployment_profile"`
	CapabilityBundles     []ArtifactRef  `json:"capability_bundles"`
	PolicyBundles         []ArtifactRef  `json:"policy_bundles"`
	EndpointReferences    []string       `json:"endpoint_references"`
	Permissions           []string       `json:"permissions"`
	Limits                Limits         `json:"limits"`
	Features              Features       `json:"features"`
	OfflineBundleDigest   string         `json:"offline_bundle_digest"`
	ProfileBindingDigest  string         `json:"profile_binding_digest"`
	CapabilityGraphDigest string         `json:"capability_graph_digest"`
	CompositionDigest     string         `json:"composition_digest,omitempty"`
}

type Candidate struct{ state *candidateState }

type candidateState struct {
	request              Request
	ordered              []VerifiedLayer
	bindings             []LayerBinding
	deployment           ArtifactRef
	capabilities         []ArtifactRef
	policies             []ArtifactRef
	endpoints            []string
	permissions          []string
	limits               Limits
	features             Features
	offlineBundleDigest  string
	profileBindingDigest string
}

type ValidatedResolvedProfile struct {
	digest string
	bytes  []byte
}

func (value ValidatedResolvedProfile) Digest() string { return value.digest }
func (value ValidatedResolvedProfile) CanonicalBytes() []byte {
	return append([]byte(nil), value.bytes...)
}
func (value ValidatedResolvedProfile) Value() ResolvedProfile {
	var profile ResolvedProfile
	_ = json.Unmarshal(value.bytes, &profile)
	return profile
}

func (candidate Candidate) ProfileBindingDigest() string {
	if candidate.state == nil {
		return ""
	}
	return candidate.state.profileBindingDigest
}
func (candidate Candidate) CapabilityReferences() []ArtifactRef {
	if candidate.state == nil {
		return nil
	}
	return append([]ArtifactRef(nil), candidate.state.capabilities...)
}
func (candidate Candidate) Request() Request {
	if candidate.state == nil {
		return Request{}
	}
	return candidate.state.request
}
func (candidate Candidate) DeploymentProfile() ArtifactRef {
	if candidate.state == nil {
		return ArtifactRef{}
	}
	return candidate.state.deployment
}
func (candidate Candidate) PolicyReferences() []ArtifactRef {
	if candidate.state == nil {
		return nil
	}
	return append([]ArtifactRef(nil), candidate.state.policies...)
}
