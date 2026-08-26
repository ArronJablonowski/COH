package skilldiscovery

import (
	"context"
	"crypto/subtle"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

type resourceResultWire struct {
	SkillName        string       `json:"skill_name"`
	ManifestDigest   string       `json:"manifest_digest"`
	ResourceName     string       `json:"resource_name"`
	Artifact         artifactWire `json:"artifact"`
	ProvenanceDigest string       `json:"provenance_digest"`
	ResultDigest     string       `json:"result_digest"`
	Replayed         bool         `json:"replayed"`
}

type recordWire struct {
	SchemaVersion            string              `json:"schema_version"`
	ContractVersion          string              `json:"contract_version"`
	Case                     caseWire            `json:"case"`
	TaskID                   string              `json:"task_id"`
	ActorID                  string              `json:"actor_id"`
	PolicyDigest             string              `json:"policy_digest"`
	RequiredPermission       string              `json:"required_permission"`
	Operation                Phase               `json:"operation"`
	IdempotencyDigest        string              `json:"idempotency_digest"`
	IntentDigest             string              `json:"intent_digest"`
	DecisionDigests          []string            `json:"decision_digests"`
	Search                   *SearchResult       `json:"search"`
	Detail                   *DetailResult       `json:"detail"`
	Resource                 *resourceResultWire `json:"resource"`
	PreviousProvenanceDigest string              `json:"previous_provenance_digest"`
	ProvenanceDigest         string              `json:"provenance_digest"`
	CreatedAt                string              `json:"created_at"`
	Revision                 uint64              `json:"revision"`
}

func idempotencyDigest(value string) string {
	digestValue, _ := digest(idempotencyDigestDomain, value)
	return digestValue
}

func searchResultDigest(value SearchResult) (string, error) {
	return digest("COH-SKILL-DISCOVERY-SEARCH-RESULT-V1\x00", struct {
		Skills         []CompactSkill `json:"skills"`
		SnapshotDigest string         `json:"snapshot_digest"`
		NextCursor     string         `json:"next_cursor"`
	}{slices.Clone(value.Skills), value.SnapshotDigest, value.NextCursor})
}

func detailResultDigest(value DetailResult) (string, error) {
	copy := cloneDetail(value)
	copy.ResultDigest = ""
	copy.Replayed = false
	return digest("COH-SKILL-DISCOVERY-DETAIL-RESULT-V1\x00", copy)
}

func resourceResultDigest(value ResourceResult) (string, error) {
	return digest("COH-SKILL-DISCOVERY-RESOURCE-RESULT-V1\x00", struct {
		SkillName        string       `json:"skill_name"`
		ManifestDigest   string       `json:"manifest_digest"`
		ResourceName     string       `json:"resource_name"`
		Artifact         artifactWire `json:"artifact"`
		ProvenanceDigest string       `json:"provenance_digest"`
	}{SkillName: value.SkillName, ManifestDigest: value.ManifestDigest,
		ResourceName: value.ResourceName, Artifact: artifactToWire(value.Artifact),
		ProvenanceDigest: value.ProvenanceDigest})
}

func recordProvenanceDigest(value Record) (string, error) {
	copy := cloneRecord(value)
	copy.ProvenanceDigest = ""
	return digest(recordProvenanceDomain, recordToWire(copy))
}

func newRecord(scope domain.CaseRef, taskID, actorID, policyDigest, permission string,
	operation Phase, idempotency, intent string,
	decisions []string, search *SearchResult, detail *DetailResult, resource *ResourceResult,
	now time.Time) (Record, error) {
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		Case: scope, TaskID: taskID, ActorID: actorID, PolicyDigest: policyDigest,
		RequiredPermission: permission, Operation: operation, IdempotencyDigest: idempotency,
		IntentDigest: intent, DecisionDigests: slices.Clone(decisions), CreatedAt: now, Revision: 1}
	if search != nil {
		copy := cloneSearch(*search)
		record.Search = &copy
	}
	if detail != nil {
		copy := cloneDetail(*detail)
		record.Detail = &copy
	}
	if resource != nil {
		copy := *resource
		record.Resource = &copy
	}
	provenance, err := recordProvenanceDigest(record)
	if err != nil {
		return Record{}, err
	}
	record.ProvenanceDigest = provenance
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateRecord(value Record) error {
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.TaskID) ||
		!uuidPattern.MatchString(value.ActorID) || !digestPattern.MatchString(value.PolicyDigest) ||
		!tokenPattern.MatchString(value.RequiredPermission) ||
		(value.Operation != CompactSearch && value.Operation != DetailExpand && value.Operation != ResourceFetch) ||
		!digestPattern.MatchString(value.IdempotencyDigest) || !digestPattern.MatchString(value.IntentDigest) ||
		len(value.DecisionDigests) == 0 || len(value.DecisionDigests) > MaximumPageSize+1 ||
		!validTime(value.CreatedAt) || value.Revision != 1 ||
		value.PreviousProvenanceDigest != "" || !digestPattern.MatchString(value.ProvenanceDigest) {
		return newError(Denied, "record_invalid", false, nil)
	}
	for _, decision := range value.DecisionDigests {
		if !digestPattern.MatchString(decision) {
			return newError(Denied, "record_decision_invalid", false, nil)
		}
	}
	resultCount := 0
	if value.Search != nil {
		resultCount++
		if err := validateSearchResult(*value.Search); err != nil {
			return newError(Denied, "record_search_invalid", false, err)
		}
	}
	if value.Detail != nil {
		resultCount++
		if err := validateDetailResult(*value.Detail); err != nil {
			return newError(Denied, "record_detail_invalid", false, err)
		}
	}
	if value.Resource != nil {
		resultCount++
		if err := validateResourceResult(*value.Resource); err != nil {
			return newError(Denied, "record_resource_invalid", false, err)
		}
	}
	if resultCount != 1 || value.Operation == CompactSearch && value.Search == nil ||
		value.Operation == DetailExpand && value.Detail == nil ||
		value.Operation == ResourceFetch && value.Resource == nil {
		return newError(Denied, "record_result_invalid", false, nil)
	}
	expected, err := recordProvenanceDigest(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(value.ProvenanceDigest)) != 1 {
		return newError(Denied, "record_provenance_invalid", false, err)
	}
	return nil
}

func (controller *Controller) loadReplay(ctx context.Context, scope domain.CaseRef, taskID string,
	operation Phase, idempotency, intent string) (Record, bool, error) {
	value, found, err := controller.store.Load(ctx, scope, taskID, operation, idempotency)
	if err != nil {
		return Record{}, false, mapDependency(ctx, "store_load_unavailable", err)
	}
	if !found {
		return Record{}, false, nil
	}
	if err := validateRecord(value); err != nil || value.Case != scope || value.TaskID != taskID ||
		value.Operation != operation || value.IdempotencyDigest != idempotency {
		return Record{}, false, newError(Denied, "stored_record_invalid", false, err)
	}
	if value.IntentDigest != intent {
		return Record{}, false, newError(Denied, "changed_replay", false, nil)
	}
	return cloneRecord(value), true, nil
}

func (controller *Controller) loadParent(ctx context.Context, scope domain.CaseRef,
	taskID, actorID, policyDigest, permission string, operation Phase, idempotencyKey string) (Record, error) {
	idempotency := idempotencyDigest(idempotencyKey)
	value, found, err := controller.store.Load(ctx, scope, taskID, operation, idempotency)
	if err != nil {
		return Record{}, mapDependency(ctx, "parent_store_unavailable", err)
	}
	if !found {
		return Record{}, newError(Denied, "parent_result_missing", false, nil)
	}
	if err := validateRecord(value); err != nil || value.Case != scope || value.TaskID != taskID ||
		value.ActorID != actorID || value.PolicyDigest != policyDigest ||
		value.RequiredPermission != permission || value.Operation != operation ||
		value.IdempotencyDigest != idempotency {
		return Record{}, newError(Denied, "parent_result_invalid", false, err)
	}
	return cloneRecord(value), nil
}

func (controller *Controller) commit(ctx context.Context, key string, candidate Record) (Record, bool, error) {
	stored, replayed, err := controller.store.Commit(ctx, key, candidate)
	if err != nil {
		return Record{}, false, mapDependency(ctx, "store_commit_unavailable", err)
	}
	if err := validateRecord(stored); err != nil || stored.Case != candidate.Case ||
		stored.TaskID != candidate.TaskID || stored.ActorID != candidate.ActorID ||
		stored.PolicyDigest != candidate.PolicyDigest ||
		stored.RequiredPermission != candidate.RequiredPermission || stored.Operation != candidate.Operation ||
		stored.IdempotencyDigest != candidate.IdempotencyDigest {
		return Record{}, false, newError(Denied, "store_result_invalid", false, err)
	}
	if stored.IntentDigest != candidate.IntentDigest {
		return Record{}, false, newError(Denied, "changed_replay", false, nil)
	}
	if replayed && !sameResult(stored, candidate) {
		return Record{}, false, newError(Denied, "stale_replay_result", false, nil)
	}
	return cloneRecord(stored), replayed, nil
}

func sameResult(left, right Record) bool {
	switch left.Operation {
	case CompactSearch:
		return left.Search != nil && right.Search != nil &&
			left.Search.ResultDigest == right.Search.ResultDigest &&
			left.Search.SnapshotDigest == right.Search.SnapshotDigest
	case DetailExpand:
		return left.Detail != nil && right.Detail != nil && left.Detail.ResultDigest == right.Detail.ResultDigest
	case ResourceFetch:
		return left.Resource != nil && right.Resource != nil && left.Resource.ResultDigest == right.Resource.ResultDigest
	default:
		return false
	}
}

func cloneRecord(value Record) Record {
	value.DecisionDigests = slices.Clone(value.DecisionDigests)
	if value.Search != nil {
		copy := cloneSearch(*value.Search)
		value.Search = &copy
	}
	if value.Detail != nil {
		copy := cloneDetail(*value.Detail)
		value.Detail = &copy
	}
	if value.Resource != nil {
		copy := *value.Resource
		value.Resource = &copy
	}
	return value
}

func recordToWire(value Record) recordWire {
	wire := recordWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		Case: caseToWire(value.Case), TaskID: value.TaskID, ActorID: value.ActorID,
		PolicyDigest: value.PolicyDigest, RequiredPermission: value.RequiredPermission,
		Operation: value.Operation, IdempotencyDigest: value.IdempotencyDigest,
		IntentDigest: value.IntentDigest, DecisionDigests: slices.Clone(value.DecisionDigests),
		PreviousProvenanceDigest: value.PreviousProvenanceDigest,
		ProvenanceDigest:         value.ProvenanceDigest, CreatedAt: formatTime(value.CreatedAt), Revision: value.Revision}
	if value.Search != nil {
		copy := cloneSearch(*value.Search)
		wire.Search = &copy
	}
	if value.Detail != nil {
		copy := cloneDetail(*value.Detail)
		wire.Detail = &copy
	}
	if value.Resource != nil {
		resource := resourceResultToWire(*value.Resource)
		wire.Resource = &resource
	}
	return wire
}

func recordFromWire(wire recordWire) (Record, error) {
	createdAt, err := parseWireTime(wire.CreatedAt)
	if err != nil {
		return Record{}, err
	}
	value := Record{SchemaVersion: wire.SchemaVersion, ContractVersion: wire.ContractVersion,
		Case: caseFromWire(wire.Case), TaskID: wire.TaskID, ActorID: wire.ActorID,
		PolicyDigest: wire.PolicyDigest, RequiredPermission: wire.RequiredPermission,
		Operation: wire.Operation, IdempotencyDigest: wire.IdempotencyDigest,
		IntentDigest: wire.IntentDigest, DecisionDigests: slices.Clone(wire.DecisionDigests),
		PreviousProvenanceDigest: wire.PreviousProvenanceDigest,
		ProvenanceDigest:         wire.ProvenanceDigest, CreatedAt: createdAt, Revision: wire.Revision}
	if wire.Search != nil {
		copy := cloneSearch(*wire.Search)
		value.Search = &copy
	}
	if wire.Detail != nil {
		copy := cloneDetail(*wire.Detail)
		value.Detail = &copy
	}
	if wire.Resource != nil {
		resource := resourceResultFromWire(*wire.Resource)
		value.Resource = &resource
	}
	return value, nil
}

func resourceResultToWire(value ResourceResult) resourceResultWire {
	return resourceResultWire{SkillName: value.SkillName, ManifestDigest: value.ManifestDigest,
		ResourceName: value.ResourceName, Artifact: artifactToWire(value.Artifact),
		ProvenanceDigest: value.ProvenanceDigest, ResultDigest: value.ResultDigest, Replayed: value.Replayed}
}

func resourceResultFromWire(value resourceResultWire) ResourceResult {
	return ResourceResult{SkillName: value.SkillName, ManifestDigest: value.ManifestDigest,
		ResourceName: value.ResourceName, Artifact: artifactFromWire(value.Artifact),
		ProvenanceDigest: value.ProvenanceDigest, ResultDigest: value.ResultDigest, Replayed: value.Replayed}
}
