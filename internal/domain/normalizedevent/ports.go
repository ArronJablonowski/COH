package normalizedevent

import (
	"context"
	"reflect"
	"time"
)

type SourceBinding struct {
	Case                   Case
	Artifact               Artifact
	ManifestDigest         string
	IngestReceiptDigest    string
	SourceProvenanceDigest string
}

type ResolvedSource struct {
	Binding SourceBinding
}

// EvidenceResolver verifies a COH-E10 immutable reference. It exposes no raw
// bytes, storage locator, key, policy source, or authorization surface.
type EvidenceResolver interface {
	ResolveEvidence(context.Context, SourceBinding) (ResolvedSource, error)
}

func VerifyEvidence(ctx context.Context, envelope ValidatedEnvelope, resolver EvidenceResolver) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if resolver == nil {
		return newError(InvalidInput, "nil_evidence_resolver", nil)
	}
	value := envelope.value
	wanted := SourceBinding{Case: value.Case, Artifact: value.Lineage.RawArtifact,
		ManifestDigest: value.Lineage.RawManifestDigest, IngestReceiptDigest: value.Lineage.IngestReceiptDigest,
		SourceProvenanceDigest: value.Lineage.SourceProvenanceDigest}
	resolved, err := resolver.ResolveEvidence(ctx, wanted)
	if err != nil {
		if contextCode := Code(err); contextCode == Canceled || contextCode == Timeout {
			return err
		}
		return newError(Unavailable, "evidence_resolution", err)
	}
	if resolved.Binding != wanted {
		return newError(Conflict, "evidence_binding_mismatch", nil)
	}
	return checkContext(ctx)
}

type DatasetReadRequest struct {
	Case    Case
	Dataset Dataset
	Cursor  string
	Page    uint32
}

type DatasetPage struct {
	Records    [][]byte
	NextCursor string
	Complete   bool
	RowsRead   uint64
	BytesRead  uint64
}

type ValidatedDatasetPage struct {
	records    []ValidatedEnvelope
	nextCursor string
	complete   bool
	rowsRead   uint64
	bytesRead  uint64
}

func (page ValidatedDatasetPage) Records() []ValidatedEnvelope {
	return append([]ValidatedEnvelope(nil), page.records...)
}

func (page ValidatedDatasetPage) NextCursor() string { return page.nextCursor }
func (page ValidatedDatasetPage) Complete() bool     { return page.complete }
func (page ValidatedDatasetPage) RowsRead() uint64   { return page.rowsRead }
func (page ValidatedDatasetPage) BytesRead() uint64  { return page.bytesRead }

// DatasetReader is the only public normalized collection access port. The
// descriptor contains immutable identities and logical positions, never a
// filesystem path, URL, SQL statement, network client, or connector handle.
type DatasetReader interface {
	ReadPage(context.Context, DatasetReadRequest) (DatasetPage, error)
}

// ReadDatasetPage applies the contract's time, page, row, byte, case, and
// immutable collection bindings around the injected reader.
func ReadDatasetPage(ctx context.Context, reader DatasetReader, request DatasetReadRequest) (ValidatedDatasetPage, error) {
	if err := checkContext(ctx); err != nil {
		return ValidatedDatasetPage{}, err
	}
	if reader == nil || !validCase(request.Case) || len(request.Cursor) > 256 ||
		request.Page >= request.Dataset.AccessProfile.MaxPages {
		return ValidatedDatasetPage{}, newError(InvalidInput, "dataset_request", nil)
	}
	if err := validateDataset(Envelope{Classification: request.Dataset.Artifact.Classification, Dataset: &request.Dataset}); err != nil {
		return ValidatedDatasetPage{}, err
	}
	deadline, hasDeadline := ctx.Deadline()
	remaining := time.Until(deadline)
	if !hasDeadline || remaining <= 0 || remaining > time.Duration(request.Dataset.AccessProfile.MaxDurationMS)*time.Millisecond {
		return ValidatedDatasetPage{}, newError(InvalidInput, "dataset_deadline", nil)
	}
	page, err := reader.ReadPage(ctx, request)
	if err != nil {
		if code := Code(err); code == Canceled || code == Timeout {
			return ValidatedDatasetPage{}, err
		}
		return ValidatedDatasetPage{}, newError(Unavailable, "dataset_read", err)
	}
	if err := checkContext(ctx); err != nil {
		return ValidatedDatasetPage{}, err
	}
	if page.RowsRead != uint64(len(page.Records)) || page.RowsRead > request.Dataset.AccessProfile.MaxRows ||
		page.BytesRead > request.Dataset.AccessProfile.MaxBytes || page.Complete != (page.NextCursor == "") ||
		!page.Complete && request.Page+1 >= request.Dataset.AccessProfile.MaxPages {
		return ValidatedDatasetPage{}, newError(Conflict, "dataset_page_bounds", nil)
	}
	validated := make([]ValidatedEnvelope, 0, len(page.Records))
	var byteCount uint64
	for _, record := range page.Records {
		byteCount += uint64(len(record))
		if byteCount > request.Dataset.AccessProfile.MaxBytes {
			return ValidatedDatasetPage{}, newError(Conflict, "dataset_page_bounds", nil)
		}
		envelope, decodeErr := Decode(ctx, record)
		if decodeErr != nil {
			return ValidatedDatasetPage{}, newError(Conflict, "dataset_record", decodeErr)
		}
		value := envelope.value
		if value.Case != request.Case || value.Dataset == nil || !sameDatasetCollection(*value.Dataset, request.Dataset) {
			return ValidatedDatasetPage{}, newError(Conflict, "dataset_record_binding", nil)
		}
		validated = append(validated, envelope)
	}
	if byteCount != page.BytesRead {
		return ValidatedDatasetPage{}, newError(Conflict, "dataset_page_bounds", nil)
	}
	return ValidatedDatasetPage{records: validated, nextCursor: page.NextCursor, complete: page.Complete,
		rowsRead: page.RowsRead, bytesRead: page.BytesRead}, nil
}

func sameDatasetCollection(left, right Dataset) bool {
	left.RowGroup, left.RowIndex = 0, 0
	right.RowGroup, right.RowIndex = 0, 0
	return reflect.DeepEqual(left, right)
}
