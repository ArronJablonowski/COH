package skilldiscovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

type decisionWire struct {
	SchemaVersion      string   `json:"schema_version"`
	ContractVersion    string   `json:"contract_version"`
	DecisionID         string   `json:"decision_id"`
	RequestID          string   `json:"request_id"`
	PolicyDigest       string   `json:"policy_digest"`
	Case               caseWire `json:"case"`
	TaskID             string   `json:"task_id"`
	ActorID            string   `json:"actor_id"`
	Phase              Phase    `json:"phase"`
	SkillName          string   `json:"skill_name"`
	ManifestDigest     string   `json:"manifest_digest"`
	RequiredPermission string   `json:"required_permission"`
	ResourceName       string   `json:"resource_name"`
	ResourceDigest     string   `json:"resource_digest"`
	QueryDigest        string   `json:"query_digest"`
	SnapshotDigest     string   `json:"snapshot_digest"`
	Cursor             string   `json:"cursor"`
	PageLimit          uint16   `json:"page_limit"`
	ParentResultDigest string   `json:"parent_result_digest"`
	Deadline           string   `json:"deadline"`
	Outcome            string   `json:"outcome"`
	Revision           uint64   `json:"revision"`
	IssuedAt           string   `json:"issued_at"`
	ExpiresAt          string   `json:"expires_at"`
}

type caseWire struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type artifactWire struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type searchIntentWire struct {
	SchemaVersion          string   `json:"schema_version"`
	ContractVersion        string   `json:"contract_version"`
	RequestID              string   `json:"request_id"`
	IdempotencyKey         string   `json:"idempotency_key"`
	Case                   caseWire `json:"case"`
	TaskID                 string   `json:"task_id"`
	ActorID                string   `json:"actor_id"`
	PolicyDigest           string   `json:"policy_digest"`
	RequiredPermission     string   `json:"required_permission"`
	Query                  string   `json:"query"`
	Limit                  uint16   `json:"limit"`
	Cursor                 string   `json:"cursor"`
	ExpectedSnapshotDigest string   `json:"expected_snapshot_digest"`
	Deadline               string   `json:"deadline"`
}

type detailIntentWire struct {
	SchemaVersion              string   `json:"schema_version"`
	ContractVersion            string   `json:"contract_version"`
	RequestID                  string   `json:"request_id"`
	IdempotencyKey             string   `json:"idempotency_key"`
	Case                       caseWire `json:"case"`
	TaskID                     string   `json:"task_id"`
	ActorID                    string   `json:"actor_id"`
	PolicyDigest               string   `json:"policy_digest"`
	RequiredPermission         string   `json:"required_permission"`
	SkillName                  string   `json:"skill_name"`
	ExpectedManifestDigest     string   `json:"expected_manifest_digest"`
	SearchIdempotencyKey       string   `json:"search_idempotency_key"`
	ExpectedSearchResultDigest string   `json:"expected_search_result_digest"`
	Deadline                   string   `json:"deadline"`
}

type resourceIntentWire struct {
	SchemaVersion              string   `json:"schema_version"`
	ContractVersion            string   `json:"contract_version"`
	RequestID                  string   `json:"request_id"`
	IdempotencyKey             string   `json:"idempotency_key"`
	Case                       caseWire `json:"case"`
	TaskID                     string   `json:"task_id"`
	ActorID                    string   `json:"actor_id"`
	PolicyDigest               string   `json:"policy_digest"`
	RequiredPermission         string   `json:"required_permission"`
	SkillName                  string   `json:"skill_name"`
	ExpectedManifestDigest     string   `json:"expected_manifest_digest"`
	ResourceName               string   `json:"resource_name"`
	ResourceDigest             string   `json:"resource_digest"`
	DetailIdempotencyKey       string   `json:"detail_idempotency_key"`
	ExpectedDetailResultDigest string   `json:"expected_detail_result_digest"`
	Deadline                   string   `json:"deadline"`
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(InvalidInput, "canonical_encoding_failed", false, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(InvalidInput, "canonical_encoding_failed", false, err)
	}
	return canonical, nil
}

func digest(domain string, value any) (string, error) {
	canonical, err := canonicalValue(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func decisionDigest(value Decision) (string, error) {
	return digest(decisionDigestDomain, decisionWire{SchemaVersion: value.SchemaVersion,
		ContractVersion: value.ContractVersion, DecisionID: value.DecisionID,
		RequestID: value.RequestID, PolicyDigest: value.PolicyDigest,
		Case: caseToWire(value.Case), TaskID: value.TaskID,
		ActorID: value.ActorID, Phase: value.Phase, SkillName: value.SkillName,
		ManifestDigest: value.ManifestDigest, RequiredPermission: value.RequiredPermission,
		ResourceName: value.ResourceName, ResourceDigest: value.ResourceDigest,
		QueryDigest: value.QueryDigest, SnapshotDigest: value.SnapshotDigest, Cursor: value.Cursor,
		PageLimit: value.PageLimit, ParentResultDigest: value.ParentResultDigest,
		Deadline: formatTime(value.Deadline),
		Outcome:  value.Outcome, Revision: value.Revision, IssuedAt: formatTime(value.IssuedAt),
		ExpiresAt: formatTime(value.ExpiresAt)})
}

// DigestDecision returns the exact digest authorities sign or attest.
func DigestDecision(value Decision) (string, error) { return decisionDigest(value) }

func queryDigest(query string) string {
	value, _ := digest("COH-SKILL-DISCOVERY-QUERY-V1\x00", query)
	return value
}

func intentDigest(value any) (string, error) {
	switch request := value.(type) {
	case SearchRequest:
		return digest(intentDigestDomain, searchIntentWire{SchemaVersion: request.SchemaVersion,
			ContractVersion: request.ContractVersion, RequestID: request.RequestID,
			IdempotencyKey: request.IdempotencyKey, Case: caseToWire(request.Case),
			TaskID: request.TaskID, ActorID: request.ActorID, PolicyDigest: request.PolicyDigest,
			RequiredPermission: request.RequiredPermission, Query: request.Query, Limit: request.Limit,
			Cursor: request.Cursor, ExpectedSnapshotDigest: request.ExpectedSnapshotDigest,
			Deadline: formatTime(request.Deadline)})
	case DetailRequest:
		return digest(intentDigestDomain, detailIntentWire{SchemaVersion: request.SchemaVersion,
			ContractVersion: request.ContractVersion, RequestID: request.RequestID,
			IdempotencyKey: request.IdempotencyKey, Case: caseToWire(request.Case),
			TaskID: request.TaskID, ActorID: request.ActorID, PolicyDigest: request.PolicyDigest,
			RequiredPermission: request.RequiredPermission, SkillName: request.SkillName,
			ExpectedManifestDigest:     request.ExpectedManifestDigest,
			SearchIdempotencyKey:       request.SearchIdempotencyKey,
			ExpectedSearchResultDigest: request.ExpectedSearchResultDigest,
			Deadline:                   formatTime(request.Deadline)})
	case ResourceRequest:
		return digest(intentDigestDomain, resourceIntentWire{SchemaVersion: request.SchemaVersion,
			ContractVersion: request.ContractVersion, RequestID: request.RequestID,
			IdempotencyKey: request.IdempotencyKey, Case: caseToWire(request.Case),
			TaskID: request.TaskID, ActorID: request.ActorID, PolicyDigest: request.PolicyDigest,
			RequiredPermission: request.RequiredPermission, SkillName: request.SkillName,
			ExpectedManifestDigest: request.ExpectedManifestDigest, ResourceName: request.ResourceName,
			ResourceDigest: request.ResourceDigest, DetailIdempotencyKey: request.DetailIdempotencyKey,
			ExpectedDetailResultDigest: request.ExpectedDetailResultDigest,
			Deadline:                   formatTime(request.Deadline)})
	default:
		return "", newError(InvalidInput, "intent_type_invalid", false, nil)
	}
}

func cursorFor(request SearchRequest, snapshot string, offset int) string {
	value, _ := digest(cursorDomain, struct {
		Case       caseWire `json:"case"`
		TaskID     string   `json:"task_id"`
		ActorID    string   `json:"actor_id"`
		Policy     string   `json:"policy_digest"`
		Permission string   `json:"required_permission"`
		Query      string   `json:"query_digest"`
		Snapshot   string   `json:"snapshot_digest"`
		Offset     int      `json:"offset"`
	}{caseToWire(request.Case), request.TaskID, request.ActorID, request.PolicyDigest,
		request.RequiredPermission, queryDigest(request.Query), snapshot, offset})
	return value
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func artifactToWire(value domain.ArtifactRef) artifactWire {
	return artifactWire{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func artifactFromWire(value artifactWire) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func operationRequestID(requestID string, phase Phase, skillName string, ordinal int) string {
	sum := sha256.Sum256([]byte("COH-SKILL-DISCOVERY-REQUEST-ID-V1\x00" + requestID + "\x00" +
		string(phase) + "\x00" + skillName + fmt.Sprintf("\x00%d", ordinal)))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timestampLayout)
}
