package redaction

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneEvidence(value EvidenceReference) EvidenceReference { return value }

func cloneHead(value CustodyHead) CustodyHead {
	value.LastRecordAt = clonePointer(value.LastRecordAt)
	return value
}

func cloneCommand(value Command) Command {
	value.Source = cloneEvidence(value.Source)
	value.ExpectedCustodyHead = cloneHead(value.ExpectedCustodyHead)
	return value
}

func cloneRule(value RuleSet) RuleSet {
	value.AllowedMediaTypes = append([]string(nil), value.AllowedMediaTypes...)
	value.PermittedModes = append([]ReplacementMode(nil), value.PermittedModes...)
	value.MaskDigest = clonePointer(value.MaskDigest)
	value.TokenDigest = clonePointer(value.TokenDigest)
	return value
}

func clonePlan(value ApprovedPlan) ApprovedPlan {
	value.Source = cloneEvidence(value.Source)
	value.Spans = append([]PlanSpan(nil), value.Spans...)
	return value
}

func cloneMapping(value Mapping) Mapping {
	value.Source = cloneEvidence(value.Source)
	value.Entries = append([]MappingEntry(nil), value.Entries...)
	return value
}

func cloneAuthorization(value AuthorizationRequest) AuthorizationRequest {
	value.Command = cloneCommand(value.Command)
	value.Plan = clonePlan(value.Plan)
	value.CurrentCustodyHead = cloneHead(value.CurrentCustodyHead)
	return value
}

func cloneDecision(value Decision) Decision {
	value.ExpectedCustodyHead = cloneHead(value.ExpectedCustodyHead)
	return value
}

func cloneRecord(value Record) Record {
	value.Command = cloneCommand(value.Command)
	value.Derived = cloneEvidence(value.Derived)
	value.MappingReference = cloneEvidence(value.MappingReference)
	return value
}

func cloneReceipt(value Receipt) Receipt {
	value.Derived = cloneEvidence(value.Derived)
	value.MappingReference = cloneEvidence(value.MappingReference)
	return value
}

func clonePublished(value *PublishedEvidence) *PublishedEvidence {
	if value == nil {
		return nil
	}
	copyValue := *value
	copyValue.Reference = cloneEvidence(value.Reference)
	return &copyValue
}

func cloneProgress(value Progress) Progress {
	value.Derived = clonePublished(value.Derived)
	value.Mapping = clonePublished(value.Mapping)
	value.MappingDigest = clonePointer(value.MappingDigest)
	value.Custody = clonePointer(value.Custody)
	return value
}
