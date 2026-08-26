// Package skilldiscovery exposes skills progressively: compact identity first,
// signed details second, and one immutable resource reference last.
package skilldiscovery

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

const (
	SearchSchemaVersion      = "coh.skill-discovery-search/v1"
	DetailSchemaVersion      = "coh.skill-discovery-detail/v1"
	ResourceSchemaVersion    = "coh.skill-discovery-resource/v1"
	DecisionSchemaVersion    = "coh.skill-discovery-decision/v1"
	RecordSchemaVersion      = "coh.skill-discovery-record/v1"
	ContractVersion          = "1.0.0"
	MaximumPageSize          = 32
	MaximumQueryBytes        = 128
	MaximumIdempotencyBytes  = 256
	MaximumDiscoveryValidity = 24 * time.Hour
	decisionDigestDomain     = "COH-SKILL-DISCOVERY-DECISION-V1\x00"
	intentDigestDomain       = "COH-SKILL-DISCOVERY-INTENT-V1\x00"
	recordProvenanceDomain   = "COH-SKILL-DISCOVERY-RECORD-V1\x00"
	cursorDomain             = "COH-SKILL-DISCOVERY-CURSOR-V1\x00"
	idempotencyDigestDomain  = "COH-SKILL-DISCOVERY-IDEMPOTENCY-V1\x00"
)

type Phase string

const (
	CompactSearch Phase = "compact_search"
	DetailExpand  Phase = "detail_expand"
	ResourceFetch Phase = "resource_fetch"
)

type SearchRequest struct {
	SchemaVersion          string         `json:"schema_version"`
	ContractVersion        string         `json:"contract_version"`
	RequestID              string         `json:"request_id"`
	IdempotencyKey         string         `json:"idempotency_key"`
	Case                   domain.CaseRef `json:"case"`
	TaskID                 string         `json:"task_id"`
	ActorID                string         `json:"actor_id"`
	PolicyDigest           string         `json:"policy_digest"`
	RequiredPermission     string         `json:"required_permission"`
	Query                  string         `json:"query"`
	Limit                  uint16         `json:"limit"`
	Cursor                 string         `json:"cursor"`
	ExpectedSnapshotDigest string         `json:"expected_snapshot_digest"`
	Deadline               time.Time      `json:"deadline"`
}

type DetailRequest struct {
	SchemaVersion              string         `json:"schema_version"`
	ContractVersion            string         `json:"contract_version"`
	RequestID                  string         `json:"request_id"`
	IdempotencyKey             string         `json:"idempotency_key"`
	Case                       domain.CaseRef `json:"case"`
	TaskID                     string         `json:"task_id"`
	ActorID                    string         `json:"actor_id"`
	PolicyDigest               string         `json:"policy_digest"`
	RequiredPermission         string         `json:"required_permission"`
	SkillName                  string         `json:"skill_name"`
	ExpectedManifestDigest     string         `json:"expected_manifest_digest"`
	SearchIdempotencyKey       string         `json:"search_idempotency_key"`
	ExpectedSearchResultDigest string         `json:"expected_search_result_digest"`
	Deadline                   time.Time      `json:"deadline"`
}

type ResourceRequest struct {
	SchemaVersion              string         `json:"schema_version"`
	ContractVersion            string         `json:"contract_version"`
	RequestID                  string         `json:"request_id"`
	IdempotencyKey             string         `json:"idempotency_key"`
	Case                       domain.CaseRef `json:"case"`
	TaskID                     string         `json:"task_id"`
	ActorID                    string         `json:"actor_id"`
	PolicyDigest               string         `json:"policy_digest"`
	RequiredPermission         string         `json:"required_permission"`
	SkillName                  string         `json:"skill_name"`
	ExpectedManifestDigest     string         `json:"expected_manifest_digest"`
	ResourceName               string         `json:"resource_name"`
	ResourceDigest             string         `json:"resource_digest"`
	DetailIdempotencyKey       string         `json:"detail_idempotency_key"`
	ExpectedDetailResultDigest string         `json:"expected_detail_result_digest"`
	Deadline                   time.Time      `json:"deadline"`
}

type AuthorizationRequest struct {
	RequestID          string
	Case               domain.CaseRef
	TaskID             string
	ActorID            string
	PolicyDigest       string
	Phase              Phase
	SkillName          string
	ManifestDigest     string
	RequiredPermission string
	ResourceName       string
	ResourceDigest     string
	QueryDigest        string
	SnapshotDigest     string
	Cursor             string
	PageLimit          uint16
	ParentResultDigest string
	Deadline           time.Time
}

type Decision struct {
	SchemaVersion      string         `json:"schema_version"`
	ContractVersion    string         `json:"contract_version"`
	DecisionID         string         `json:"decision_id"`
	DecisionDigest     string         `json:"decision_digest"`
	RequestID          string         `json:"request_id"`
	PolicyDigest       string         `json:"policy_digest"`
	Case               domain.CaseRef `json:"case"`
	TaskID             string         `json:"task_id"`
	ActorID            string         `json:"actor_id"`
	Phase              Phase          `json:"phase"`
	SkillName          string         `json:"skill_name"`
	ManifestDigest     string         `json:"manifest_digest"`
	RequiredPermission string         `json:"required_permission"`
	ResourceName       string         `json:"resource_name"`
	ResourceDigest     string         `json:"resource_digest"`
	QueryDigest        string         `json:"query_digest"`
	SnapshotDigest     string         `json:"snapshot_digest"`
	Cursor             string         `json:"cursor"`
	PageLimit          uint16         `json:"page_limit"`
	ParentResultDigest string         `json:"parent_result_digest"`
	Deadline           time.Time      `json:"deadline"`
	Outcome            string         `json:"outcome"`
	Revision           uint64         `json:"revision"`
	IssuedAt           time.Time      `json:"issued_at"`
	ExpiresAt          time.Time      `json:"expires_at"`
}

type CompactSkill struct {
	SkillName        string `json:"skill_name"`
	SkillVersion     string `json:"skill_version"`
	ManifestDigest   string `json:"manifest_digest"`
	ProvenanceDigest string `json:"provenance_digest"`
}

type SearchResult struct {
	Skills         []CompactSkill `json:"skills"`
	SnapshotDigest string         `json:"snapshot_digest"`
	NextCursor     string         `json:"next_cursor"`
	ResultDigest   string         `json:"result_digest"`
	Replayed       bool           `json:"replayed"`
}

type DetailResult struct {
	SkillName        string                   `json:"skill_name"`
	SkillVersion     string                   `json:"skill_version"`
	ManifestDigest   string                   `json:"manifest_digest"`
	ContentDigest    string                   `json:"content_digest"`
	Resources        []skillregistry.Resource `json:"resources"`
	Permissions      []string                 `json:"permissions"`
	OwnerActorID     string                   `json:"owner_actor_id"`
	ReviewID         string                   `json:"review_id"`
	ReviewRevision   uint64                   `json:"review_revision"`
	ProvenanceDigest string                   `json:"provenance_digest"`
	ResultDigest     string                   `json:"result_digest"`
	Replayed         bool                     `json:"replayed"`
}

type ResourceResult struct {
	SkillName        string             `json:"skill_name"`
	ManifestDigest   string             `json:"manifest_digest"`
	ResourceName     string             `json:"resource_name"`
	Artifact         domain.ArtifactRef `json:"artifact"`
	ProvenanceDigest string             `json:"provenance_digest"`
	ResultDigest     string             `json:"result_digest"`
	Replayed         bool               `json:"replayed"`
}

type RetrievalRequest struct {
	RequestID        string
	Case             domain.CaseRef
	TaskID           string
	ActorID          string
	PolicyDigest     string
	SkillName        string
	ManifestDigest   string
	Resource         skillregistry.Resource
	ProvenanceDigest string
	DecisionDigest   string
	Deadline         time.Time
}

type Record struct {
	SchemaVersion            string          `json:"schema_version"`
	ContractVersion          string          `json:"contract_version"`
	Case                     domain.CaseRef  `json:"case"`
	TaskID                   string          `json:"task_id"`
	ActorID                  string          `json:"actor_id"`
	PolicyDigest             string          `json:"policy_digest"`
	RequiredPermission       string          `json:"required_permission"`
	Operation                Phase           `json:"operation"`
	IdempotencyDigest        string          `json:"idempotency_digest"`
	IntentDigest             string          `json:"intent_digest"`
	DecisionDigests          []string        `json:"decision_digests"`
	Search                   *SearchResult   `json:"search"`
	Detail                   *DetailResult   `json:"detail"`
	Resource                 *ResourceResult `json:"resource"`
	PreviousProvenanceDigest string          `json:"previous_provenance_digest"`
	ProvenanceDigest         string          `json:"provenance_digest"`
	CreatedAt                time.Time       `json:"created_at"`
	Revision                 uint64          `json:"revision"`
}

// Authority supplies freshly resolved policy and signature authority. The
// discovery controller recomputes and validates every returned decision.
type Authority interface {
	AuthorizeDiscovery(context.Context, AuthorizationRequest) (Decision,
		skillregistry.AccessDecision, skillregistry.ResolutionAuthority, error)
}

// Registry intentionally omits Change; discovery cannot promote or revoke.
type Registry interface {
	Resolve(context.Context, skillregistry.ResolveRequest, skillregistry.AccessDecision,
		skillregistry.ResolutionAuthority) (skillregistry.ResolvedSkill, error)
}

// Retriever can resolve one already-signed resource to one immutable reference.
// It grants no HTTP, shell, filesystem-write, connector, or executor handle.
type Retriever interface {
	ResolveResource(context.Context, RetrievalRequest) (domain.ArtifactRef, error)
}

// Store is the crash-recovery and changed-replay boundary.
type Store interface {
	Load(context.Context, domain.CaseRef, string, Phase, string) (Record, bool, error)
	Commit(context.Context, string, Record) (Record, bool, error)
}

type Clock interface{ Now() time.Time }
