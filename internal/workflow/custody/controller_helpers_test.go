package custody

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type custodyTestClock struct{ now time.Time }

func (value *custodyTestClock) Now() time.Time { return value.now }

type custodyTestAuthority struct {
	mu         sync.Mutex
	requests   []AuthorizationRequest
	deny       bool
	denyReason DecisionReason
	err        error
}

func (value *custodyTestAuthority) AuthorizeCustody(_ context.Context,
	request AuthorizationRequest) (Decision, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.requests = append(value.requests, request)
	if value.err != nil {
		return Decision{}, value.err
	}
	outcome, reason := Allow, ReasonAuthorized
	if value.deny {
		outcome, reason = Deny, value.denyReason
		if reason == "" {
			reason = ReasonAuthorityDenied
		}
	}
	decision := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID:          deterministicUUID("COH-CUSTODY-TEST-DECISION-V1\x00", request.AuthorizationDigest),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Operation: request.Command.Operation, Phase: request.Command.Phase, Case: request.Command.Case,
		ActorID: request.Command.ActorID, ActorRevision: request.Command.ActorRevision,
		ExpectedCaseRevision: request.CaseRevision, ExpectedHead: cloneHead(request.CurrentHead),
		PolicyDigest: request.Command.PolicyDigest, RevocationDigest: fixtureDigest("revocation"),
		Outcome: outcome, ReasonCode: reason, IssuedAt: custodyFixtureTime,
		ExpiresAt: request.Command.Deadline, Revision: 1}
	decision.DecisionDigest, _ = DecisionBindingDigest(decision)
	return decision, nil
}

type custodyTestCases struct {
	current  CaseSnapshot
	receipts map[string]LifecycleReceiptSnapshot
	err      error
}

func (value *custodyTestCases) LoadCase(_ context.Context, _ domain.CaseRef) (CaseSnapshot, bool, error) {
	if value.err != nil {
		return CaseSnapshot{}, false, value.err
	}
	return value.current, true, nil
}

func (value *custodyTestCases) ResolveLifecycleReceipt(_ context.Context, _ domain.CaseRef,
	digest string) (LifecycleReceiptSnapshot, bool, error) {
	if value.err != nil {
		return LifecycleReceiptSnapshot{}, false, value.err
	}
	receipt, found := value.receipts[digest]
	return receipt, found, nil
}

type custodyTestEvidence struct {
	mu      sync.Mutex
	values  map[string]VerifiedEvidence
	resolve int
	err     error
}

func (value *custodyTestEvidence) ResolveEvidence(_ context.Context, _ domain.CaseRef,
	reference EvidenceReference) (VerifiedEvidence, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.resolve++
	if value.err != nil {
		return VerifiedEvidence{}, value.err
	}
	result, found := value.values[evidenceKey(reference)]
	if !found {
		return VerifiedEvidence{}, errors.New("not found")
	}
	result.ParentArtifacts = cloneArtifactSlice(result.ParentArtifacts)
	result.ParentManifestDigests = cloneStrings(result.ParentManifestDigests)
	return result, nil
}

type custodyTestLedger struct {
	mu       sync.Mutex
	head     Head
	records  []Record
	receipts map[string]Receipt
	byDigest map[string]Receipt
	intents  map[string]string
	fail     error
}

func (value *custodyTestLedger) LoadHead(_ context.Context, _ domain.CaseRef) (Head, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.fail != nil {
		return Head{}, value.fail
	}
	return cloneHead(value.head), nil
}

func (value *custodyTestLedger) Recover(_ context.Context, _ domain.CaseRef,
	idempotency string) (Receipt, bool, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.fail != nil {
		return Receipt{}, false, value.fail
	}
	receipt, found := value.receipts[idempotency]
	return receipt, found, nil
}

func (value *custodyTestLedger) ResolveReceipt(_ context.Context, _ domain.CaseRef,
	receiptDigest string) (Receipt, bool, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.fail != nil {
		return Receipt{}, false, value.fail
	}
	receipt, found := value.byDigest[receiptDigest]
	return receipt, found, nil
}

func (value *custodyTestLedger) Append(_ context.Context, _ string, intent string, expected Head,
	record Record, receipt Receipt) (Receipt, bool, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.fail != nil {
		return Receipt{}, false, value.fail
	}
	if stored, found := value.receipts[receipt.IdempotencyDigest]; found {
		if value.intents[receipt.IdempotencyDigest] != intent {
			return Receipt{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return stored, true, nil
	}
	if !sameHead(value.head, expected) {
		return Receipt{}, false, newError(Conflict, "stale_head", true, nil)
	}
	if validateRecord(record) != nil || validateReceipt(receipt) != nil {
		return Receipt{}, false, errors.New("invalid commit")
	}
	value.records = append(value.records, cloneRecord(record))
	value.receipts[receipt.IdempotencyDigest] = receipt
	value.byDigest[receipt.ReceiptDigest] = receipt
	value.intents[receipt.IdempotencyDigest] = intent
	last := record.OccurredAt
	value.head = Head{Case: record.Case, Sequence: record.Sequence, ChainHash: record.ChainHash, LastRecordAt: &last}
	return receipt, false, nil
}

func (value *custodyTestLedger) Read(_ context.Context, _ domain.CaseRef, after uint64,
	limit uint16) ([]Record, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.fail != nil {
		return nil, value.fail
	}
	result := make([]Record, 0, limit)
	for _, record := range value.records {
		if record.Sequence > after && len(result) < int(limit) {
			result = append(result, cloneRecord(record))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Sequence < result[right].Sequence })
	return result, nil
}

type custodyTestAuditor struct {
	mu       sync.Mutex
	proofs   map[string]AuditProof
	events   []tamperaudit.Event
	fail     bool
	sequence uint64
}

func (value *custodyTestAuditor) AppendCustodyEvent(_ context.Context,
	event tamperaudit.Event) (AuditProof, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.fail {
		return AuditProof{}, errors.New("audit unavailable")
	}
	eventDigest, err := auditEventBindingDigest(event)
	if err != nil {
		return AuditProof{}, err
	}
	if proof, found := value.proofs[eventDigest]; found {
		return proof, nil
	}
	value.sequence++
	proof := AuditProof{EventDigest: eventDigest, Sequence: value.sequence,
		ChainHash: fixtureDigest("audit.chain." + eventDigest)}
	value.proofs[eventDigest] = proof
	value.events = append(value.events, event)
	return proof, nil
}

func (value *custodyTestAuditor) VerifyCustodyEvent(_ context.Context, _ domain.CaseRef,
	eventDigest, _ string) (AuditProof, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	proof, found := value.proofs[eventDigest]
	if !found {
		return AuditProof{}, errors.New("audit event missing")
	}
	return proof, nil
}

func custodyControllerFixture(t interface {
	Helper()
	Fatal(...any)
}) (*Controller, Command,
	*custodyTestAuthority, *custodyTestCases, *custodyTestEvidence, *custodyTestLedger, *custodyTestAuditor) {
	t.Helper()
	command := custodyCommandFixture(Acquire, Completed)
	command.ExpectedHead = Head{Case: command.Case, ChainHash: GenesisHash}
	command.ExpectedCaseRevision = 2
	command.Deadline = custodyFixtureTime.Add(time.Minute)
	current := CaseSnapshot{Case: command.Case, State: "open", Classification: "restricted", Revision: 2,
		RetentionPolicyDigest: fixtureDigest("retention"), RetainUntil: custodyFixtureTime.Add(-time.Hour),
		ProvenanceDigest: fixtureDigest("case.provenance")}
	authority := &custodyTestAuthority{}
	cases := &custodyTestCases{current: current, receipts: make(map[string]LifecycleReceiptSnapshot)}
	evidenceValue := VerifiedEvidence{Reference: command.Subject, SourceIdentityDigest: *command.SourceIdentityDigest,
		VerificationDigest: fixtureDigest("evidence.verified")}
	evidence := &custodyTestEvidence{values: map[string]VerifiedEvidence{evidenceKey(command.Subject): evidenceValue}}
	ledger := &custodyTestLedger{head: cloneHead(command.ExpectedHead), receipts: make(map[string]Receipt),
		byDigest: make(map[string]Receipt), intents: make(map[string]string)}
	auditor := &custodyTestAuditor{proofs: make(map[string]AuditProof)}
	controller, err := New(authority, cases, evidence, ledger, auditor, &custodyTestClock{now: custodyFixtureTime})
	if err != nil {
		t.Fatal(err)
	}
	return controller, command, authority, cases, evidence, ledger, auditor
}
