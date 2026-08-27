package queryevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const MaximumDocumentBytes = 1 << 20

func DecodeRecord(ctx context.Context, input []byte) (Record, []byte, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, nil, err
	}
	if len(input) == 0 || len(input) > MaximumDocumentBytes {
		return Record{}, nil, newError(InvalidInput, "document_size", nil)
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return Record{}, nil, newError(InvalidInput, "document_decoding", err)
	}
	var value Record
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&value); err != nil {
		return Record{}, nil, newError(InvalidInput, "document_decoding", err)
	}
	if _, err = decoder.Token(); err != io.EOF {
		return Record{}, nil, newError(InvalidInput, "document_decoding", err)
	}
	if err = VerifyRecord(value); err != nil {
		return Record{}, nil, err
	}
	if err = contextError(ctx); err != nil {
		return Record{}, nil, err
	}
	return value, append([]byte(nil), canonical...), nil
}
