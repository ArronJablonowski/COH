package subagentdag

func cloneClaim(value Claim) Claim {
	copyValue := value
	copyValue.EvidenceRefs = append([]string{}, value.EvidenceRefs...)
	copyValue.CounterevidenceRefs = append([]string{}, value.CounterevidenceRefs...)
	copyValue.UnknownDigests = append([]string{}, value.UnknownDigests...)
	copyValue.RecommendedNextStepDigests = append([]string{}, value.RecommendedNextStepDigests...)
	return copyValue
}

func cloneFinding(value Finding) Finding {
	copyValue := value
	copyValue.EvidenceRefs = append([]string{}, value.EvidenceRefs...)
	copyValue.CounterevidenceRefs = append([]string{}, value.CounterevidenceRefs...)
	copyValue.UnknownDigests = append([]string{}, value.UnknownDigests...)
	copyValue.RecommendedNextStepDigests = append([]string{}, value.RecommendedNextStepDigests...)
	return copyValue
}

func cloneStructuredResult(value StructuredResult) StructuredResult {
	copyValue := value
	copyValue.Claims = make([]Claim, len(value.Claims))
	for index := range value.Claims {
		copyValue.Claims[index] = cloneClaim(value.Claims[index])
	}
	copyValue.Findings = make([]Finding, len(value.Findings))
	for index := range value.Findings {
		copyValue.Findings[index] = cloneFinding(value.Findings[index])
	}
	return copyValue
}

func cloneResultPointer(value *StructuredResult) *StructuredResult {
	if value == nil {
		return nil
	}
	copyValue := cloneStructuredResult(*value)
	return &copyValue
}

func cloneCancellation(value *CancellationAck) *CancellationAck {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneTask(value Task) Task {
	copyValue := value
	copyValue.ParentTaskIDs = append([]string{}, value.ParentTaskIDs...)
	copyValue.InputRefs = append([]string{}, value.InputRefs...)
	copyValue.Result = cloneResultPointer(value.Result)
	copyValue.Cancellation = cloneCancellation(value.Cancellation)
	return copyValue
}

func cloneGraph(value Graph) Graph {
	copyValue := value
	copyValue.Tasks = make([]Task, len(value.Tasks))
	for index := range value.Tasks {
		copyValue.Tasks[index] = cloneTask(value.Tasks[index])
	}
	copyValue.Edges = append([]Edge{}, value.Edges...)
	copyValue.Receipts = append([]Receipt{}, value.Receipts...)
	copyValue.Cancellations = make([]CancellationRecord, len(value.Cancellations))
	for index, cancellation := range value.Cancellations {
		copyValue.Cancellations[index] = cancellation
		copyValue.Cancellations[index].TargetTaskIDs = append([]string{}, cancellation.TargetTaskIDs...)
		copyValue.Cancellations[index].Acknowledgments = append([]CancellationAck{}, cancellation.Acknowledgments...)
	}
	return copyValue
}
