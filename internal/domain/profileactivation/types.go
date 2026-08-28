// Package profileactivation defines the durable, quiescent publication state
// machine for already-verified resolved profiles. It grants no runtime action
// authority and cannot compose or validate profile artifacts.
package profileactivation

import (
	"context"
	"time"
)

const (
	ContractVersion        = "1.0.0"
	TransitionSchema       = "coh.profile-activation-transition/v1"
	ActiveProfileSchema    = "coh.active-profile/v1"
	transitionDigestDomain = "COH-PROFILE-ACTIVATION-TRANSITION-V1\x00"
	activeDigestDomain     = "COH-ACTIVE-PROFILE-V1\x00"
	intentDigestDomain     = "COH-PROFILE-ACTIVATION-INTENT-V1\x00"
)

type Mode string

const (
	Startup     Mode = "startup"
	Maintenance Mode = "maintenance"
	LiveReload  Mode = "live_hot_reload"
)

type Phase string

const (
	Prepared  Phase = "prepared"
	Quiescent Phase = "quiescent"
	Published Phase = "published"
	Active    Phase = "active"
)

type Target struct {
	DeploymentKind   string `json:"deployment_kind"`
	ConnectivityMode string `json:"connectivity_mode"`
	Platform         string `json:"platform"`
	Surface          string `json:"surface"`
}

type Candidate struct {
	ProfileID             string `json:"profile_id"`
	ProfileRevision       uint64 `json:"profile_revision"`
	Target                Target `json:"target"`
	ProfileBindingDigest  string `json:"profile_binding_digest"`
	CompositionDigest     string `json:"composition_digest"`
	CapabilityGraphDigest string `json:"capability_graph_digest"`
	InspectionDigest      string `json:"inspection_digest"`
}

type Request struct {
	TransitionID              string
	Mode                      Mode
	MaxDrainDurationMS        uint64
	Candidate                 Candidate
	ExpectedActiveRevision    uint64
	ExpectedCompositionDigest string
}

type ActiveProfile struct {
	SchemaVersion         string `json:"schema_version"`
	ContractVersion       string `json:"contract_version"`
	ProfileID             string `json:"profile_id"`
	ProfileRevision       uint64 `json:"profile_revision"`
	Target                Target `json:"target"`
	ProfileBindingDigest  string `json:"profile_binding_digest"`
	CompositionDigest     string `json:"composition_digest"`
	CapabilityGraphDigest string `json:"capability_graph_digest"`
	InspectionDigest      string `json:"inspection_digest"`
	TransitionID          string `json:"transition_id"`
	ActivatedAt           string `json:"activated_at"`
	ActiveDigest          string `json:"active_digest,omitempty"`
}

type Transition struct {
	SchemaVersion             string    `json:"schema_version"`
	ContractVersion           string    `json:"contract_version"`
	TransitionID              string    `json:"transition_id"`
	IntentDigest              string    `json:"intent_digest"`
	Mode                      Mode      `json:"mode"`
	MaxDrainDurationMS        uint64    `json:"max_drain_duration_ms"`
	Candidate                 Candidate `json:"candidate"`
	ExpectedActiveRevision    uint64    `json:"expected_active_revision"`
	ExpectedCompositionDigest string    `json:"expected_composition_digest"`
	Phase                     Phase     `json:"phase"`
	Sequence                  uint64    `json:"sequence"`
	QuiescenceDigest          string    `json:"quiescence_digest"`
	CreatedAt                 string    `json:"created_at"`
	UpdatedAt                 string    `json:"updated_at"`
	TransitionDigest          string    `json:"transition_digest,omitempty"`
}

type QuiescencePlan struct {
	TransitionID       string
	ProfileID          string
	CompositionDigest  string
	Mode               Mode
	MaxDrainDurationMS uint64
}

type QuiescenceAttestation struct {
	TransitionID      string
	AttestationDigest string
	AdmissionsStopped bool
	ActiveWork        uint64
	Durable           bool
}

type Result struct {
	Transition Transition
	Profile    ActiveProfile
	Replayed   bool
}

type Clock interface{ Now() time.Time }

type Store interface {
	LoadActive(context.Context, string, Target) (ActiveProfile, bool, error)
	LoadTransition(context.Context, string) (Transition, bool, error)
	CreateTransition(context.Context, Transition) (Transition, error)
	AdvanceTransition(context.Context, string, uint64, string, Phase, string) (Transition, error)
	Publish(context.Context, string, uint64, string, ActiveProfile, string) (Transition, error)
}

// MaintenanceGate must be idempotent by transition ID. Quiesce returns only
// after new admissions stop and bounded active work reaches zero.
type MaintenanceGate interface {
	Quiesce(context.Context, QuiescencePlan) (QuiescenceAttestation, error)
	Release(context.Context, QuiescenceAttestation) error
}
