package capabilityseam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type ValidatedBundle struct {
	digest string
	bytes  []byte
}

func (value ValidatedBundle) Digest() string { return value.digest }
func (value ValidatedBundle) CanonicalBytes() []byte {
	return append([]byte(nil), value.bytes...)
}
func (value ValidatedBundle) Value() Bundle {
	var bundle Bundle
	_ = json.Unmarshal(value.bytes, &bundle)
	return bundle
}

type ValidatedGraph struct {
	digest string
	bytes  []byte
}

func (value ValidatedGraph) Digest() string { return value.digest }
func (value ValidatedGraph) CanonicalBytes() []byte {
	return append([]byte(nil), value.bytes...)
}
func (value ValidatedGraph) Value() Graph {
	var graph Graph
	_ = json.Unmarshal(value.bytes, &graph)
	return graph
}

func DecodeBundle(ctx context.Context, input []byte) (ValidatedBundle, error) {
	canonical, bundle, err := decodeStrict[Bundle](ctx, input)
	if err != nil {
		return ValidatedBundle{}, err
	}
	if err := validateBundle(bundle); err != nil {
		return ValidatedBundle{}, err
	}
	digest := digestBytes(bundleDigestDomain, canonical)
	return ValidatedBundle{digest: digest, bytes: append([]byte(nil), canonical...)}, nil
}

func DecodeGraph(ctx context.Context, input []byte) (ValidatedGraph, error) {
	canonical, graph, err := decodeStrict[Graph](ctx, input)
	if err != nil {
		return ValidatedGraph{}, err
	}
	if err := validateGraph(graph); err != nil {
		return ValidatedGraph{}, err
	}
	want, err := graphDigest(graph)
	if err != nil || graph.GraphDigest != want {
		return ValidatedGraph{}, newError(Denied, "graph_digest")
	}
	return ValidatedGraph{digest: want, bytes: append([]byte(nil), canonical...)}, nil
}

func decodeStrict[T any](ctx context.Context, input []byte) ([]byte, T, error) {
	var value T
	if err := contextError(ctx); err != nil {
		return nil, value, err
	}
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return nil, value, newError(InvalidInput, "document_size")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, value, newError(InvalidInput, "document_decoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, value, newError(InvalidInput, "document_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, value, newError(InvalidInput, "document_decoding")
	}
	reencoded, err := json.Marshal(value)
	if err != nil {
		return nil, value, newError(InvalidInput, "document_decoding")
	}
	complete, err := domaincontract.Canonicalize(reencoded)
	if err != nil || !bytes.Equal(canonical, complete) {
		return nil, value, newError(InvalidInput, "document_shape")
	}
	if err := contextError(ctx); err != nil {
		return nil, value, err
	}
	return canonical, value, nil
}

func graphDigest(graph Graph) (string, error) {
	graph.GraphDigest = ""
	encoded, err := json.Marshal(graph)
	if err != nil {
		return "", err
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", err
	}
	return digestBytes(graphDigestDomain, canonical), nil
}

func digestBytes(domain string, canonical []byte) string {
	input := make([]byte, 0, len(domain)+len(canonical))
	input = append(input, domain...)
	input = append(input, canonical...)
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}
