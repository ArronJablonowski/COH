package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	maxTransactionMutations = 256
	maxTransactionOutbox    = 256
)

var (
	uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	domainKinds   = map[string]struct{}{
		"action": {}, "approval": {}, "artifact_manifest": {}, "case": {},
		"claim": {}, "evidence": {}, "finding": {}, "model": {},
		"query": {}, "risk": {}, "roe": {}, "run": {}, "skill": {},
		"task": {}, "timeline_event": {}, "vulnerability": {}, "memory": {}, "retrieval": {}, "subagent_dag": {},
		"case_lifecycle": {}, "custody_record": {}, "redaction_record": {}, "evidence_lifecycle": {},
		"evidence_artifact_set": {},
	}
)

func invalid(operation, field, detail string) error {
	return NewStorageError(StorageInvalidInput, operation, field, detail, nil)
}

func denied(operation, field, detail string) error {
	return NewStorageError(StorageDenied, operation, field, detail, nil)
}

func validateCase(operation, field string, value domain.CaseRef, optionalCase bool) error {
	if !uuidV7Pattern.MatchString(value.OrganizationID) || !uuidV7Pattern.MatchString(value.TenantID) {
		return invalid(operation, field, "organization and tenant must be UUIDv7 identifiers")
	}
	if value.CaseID == "" && optionalCase {
		return nil
	}
	if !uuidV7Pattern.MatchString(value.CaseID) {
		return invalid(operation, field, "case must be a UUIDv7 identifier")
	}
	return nil
}

func validateRecordKey(operation, field string, key RecordKey) error {
	optionalCase := key.Kind == "model" || key.Kind == "skill" || key.Kind == "memory"
	if err := validateCase(operation, field+".case", key.Case, optionalCase); err != nil {
		return err
	}
	if _, known := domainKinds[key.Kind]; !known || !uuidV7Pattern.MatchString(key.ID) {
		return invalid(operation, field, "kind and record UUID are invalid")
	}
	if key.Kind == "case" && key.Case.CaseID != key.ID {
		return denied(operation, field, "case record must be self-bound")
	}
	return nil
}

func validateDigest(operation, field, value string) error {
	if !digestPattern.MatchString(value) {
		return invalid(operation, field, "expected a sha256 digest")
	}
	return nil
}

func ValidateMetadataRecord(record MetadataRecord) error {
	const operation = "record"
	if err := validateRecordKey(operation, "key", record.Key); err != nil {
		return err
	}
	if record.Schema != "coh.domain/v1" || record.Revision == 0 {
		return invalid(operation, "schema", "schema and positive revision are required")
	}
	if err := validateDigest(operation, "digest", record.Digest); err != nil {
		return err
	}
	canonical, err := domaincontract.Canonicalize(record.Canonical)
	if err != nil || string(canonical) != string(record.Canonical) {
		return denied(operation, "canonical", "record is not exact COH-CJ-1 canonical JSON")
	}
	sum := sha256.Sum256(record.Canonical)
	if record.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		return denied(operation, "digest", "record digest does not match canonical bytes")
	}
	if err := validateRecordEnvelope(record); err != nil {
		return err
	}
	return nil
}

func validateRecordEnvelope(record MetadataRecord) error {
	decoded, err := domaincontract.DecodeUnique(record.Canonical)
	object, ok := decoded.(map[string]any)
	if err != nil || !ok {
		return denied("record", "canonical", "record envelope is invalid")
	}
	if object["schema"] != record.Schema || object["kind"] != record.Key.Kind || object["id"] != record.Key.ID ||
		object["organization_id"] != record.Key.Case.OrganizationID || object["tenant_id"] != record.Key.Case.TenantID {
		return denied("record", "canonical", "record envelope identity differs from key")
	}
	caseID := object["case_id"]
	if record.Key.Case.CaseID == "" {
		if caseID != nil {
			return denied("record", "canonical.case_id", "catalog record must use null case identity")
		}
	} else if caseID != record.Key.Case.CaseID {
		return denied("record", "canonical.case_id", "record case identity differs from key")
	}
	revision, ok := object["revision"].(json.Number)
	if !ok || revision.String() != strconv.FormatUint(record.Revision, 10) {
		return denied("record", "canonical.revision", "record revision differs from envelope")
	}
	return nil
}

func ValidateTransaction(transaction Transaction) error {
	const operation = "transact"
	if transaction.ContractVersion != StorageContractVersion {
		return invalid(operation, "contract_version", "unsupported storage contract")
	}
	if !validOpaque(transaction.IdempotencyKey, 1, 256) {
		return invalid(operation, "idempotency_key", "bounded UTF-8 key is required")
	}
	if len(transaction.Mutations) == 0 || len(transaction.Mutations) > maxTransactionMutations || len(transaction.Outbox) > maxTransactionOutbox {
		return invalid(operation, "transaction", "mutation or outbox count is outside bounds")
	}
	keys := make([]string, 0, len(transaction.Mutations))
	organizationID := transaction.Mutations[0].Key.Case.OrganizationID
	tenantID := transaction.Mutations[0].Key.Case.TenantID
	for index, mutation := range transaction.Mutations {
		field := "mutations[" + itoa(index) + "]"
		if err := validateMutation(operation, field, mutation); err != nil {
			return err
		}
		if mutation.Key.Case.OrganizationID != organizationID || mutation.Key.Case.TenantID != tenantID {
			return denied(operation, field+".key", "transaction crosses organization or tenant scope")
		}
		keys = append(keys, recordKeyString(mutation.Key))
	}
	if !sort.StringsAreSorted(keys) || hasDuplicate(keys) {
		return invalid(operation, "mutations", "mutations must be uniquely sorted by record key")
	}
	outboxIDs := make([]string, 0, len(transaction.Outbox))
	for index, message := range transaction.Outbox {
		if err := validateOutboxMessage(operation, "outbox["+itoa(index)+"]", message); err != nil {
			return err
		}
		if message.Case.OrganizationID != organizationID || message.Case.TenantID != tenantID {
			return denied(operation, "outbox["+itoa(index)+"].case", "transaction crosses organization or tenant scope")
		}
		outboxIDs = append(outboxIDs, message.ID)
	}
	if !sort.StringsAreSorted(outboxIDs) || hasDuplicate(outboxIDs) {
		return invalid(operation, "outbox", "outbox messages must be uniquely sorted by ID")
	}
	return nil
}

func validateMutation(operation, field string, mutation Mutation) error {
	if err := validateRecordKey(operation, field+".key", mutation.Key); err != nil {
		return err
	}
	switch mutation.Kind {
	case MutationPut:
		if mutation.Record == nil || mutation.Record.Key != mutation.Key || mutation.Record.Revision != mutation.ExpectedRevision+1 {
			return invalid(operation, field, "put record must match key and next revision")
		}
		return ValidateMetadataRecord(*mutation.Record)
	case MutationDelete:
		if mutation.Record != nil || mutation.ExpectedRevision == 0 {
			return invalid(operation, field, "delete requires an existing expected revision and no record")
		}
		return nil
	default:
		return invalid(operation, field+".kind", "unsupported mutation kind")
	}
}

func validateOutboxMessage(operation, field string, message OutboxMessage) error {
	if !uuidV7Pattern.MatchString(message.ID) || !tokenPattern.MatchString(message.Topic) {
		return invalid(operation, field, "message UUID and topic are invalid")
	}
	if err := validateCase(operation, field+".case", message.Case, false); err != nil {
		return err
	}
	if !validOpaque(message.PayloadRef, 1, 1024) {
		return invalid(operation, field+".payload_ref", "bounded immutable reference is required")
	}
	return validateDigest(operation, field+".payload_digest", message.PayloadDigest)
}

func ValidateOutboxClaim(claim OutboxClaim) error {
	if !uuidV7Pattern.MatchString(claim.OrganizationID) || !uuidV7Pattern.MatchString(claim.TenantID) || !tokenPattern.MatchString(claim.WorkerID) {
		return invalid("claim_outbox", "scope", "organization, tenant, and worker are invalid")
	}
	if claim.Limit == 0 || claim.Limit > 256 || claim.LeaseUntil.IsZero() || claim.LeaseUntil.Location() != time.UTC {
		return invalid("claim_outbox", "lease", "limit and UTC lease deadline are required")
	}
	return nil
}

func ValidateOutboxSettlement(settlement OutboxSettlement) error {
	if !uuidV7Pattern.MatchString(settlement.OrganizationID) || !uuidV7Pattern.MatchString(settlement.TenantID) {
		return invalid("settle_outbox", "scope", "organization and tenant must be UUIDv7 identifiers")
	}
	if !uuidV7Pattern.MatchString(settlement.MessageID) || !uuidV7Pattern.MatchString(settlement.LeaseID) {
		return invalid("settle_outbox", "identity", "message and lease must be UUIDv7 identifiers")
	}
	switch settlement.Outcome {
	case OutboxDelivered, OutboxRetry, OutboxDeadLetter:
	default:
		return invalid("settle_outbox", "outcome", "unsupported outbox outcome")
	}
	if settlement.EvidenceDigest != "" {
		return validateDigest("settle_outbox", "evidence_digest", settlement.EvidenceDigest)
	}
	return nil
}

func ValidateMigrationPlan(plan MigrationPlan) error {
	if plan.ContractVersion != StorageContractVersion || !tokenPattern.MatchString(plan.Component) || plan.Version == 0 {
		return invalid("migrate", "plan", "contract, component, and version are required")
	}
	if err := validateDigest("migrate", "checksum", plan.Checksum); err != nil {
		return err
	}
	if err := validateDigest("migrate", "backup_digest", plan.BackupDigest); err != nil {
		return err
	}
	if plan.Direction != MigrationApply && plan.Direction != MigrationRollback {
		return invalid("migrate", "direction", "unsupported migration direction")
	}
	return nil
}

func validOpaque(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum && strings.TrimSpace(value) == value
}

func recordKeyString(key RecordKey) string {
	return key.Case.OrganizationID + "/" + key.Case.TenantID + "/" + key.Case.CaseID + "/" + key.Kind + "/" + key.ID
}

func hasDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
