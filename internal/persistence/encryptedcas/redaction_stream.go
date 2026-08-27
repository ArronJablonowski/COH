package encryptedcas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

type transformStream struct {
	source      *plaintextReader
	plan        redaction.ApprovedPlan
	mask        byte
	token       []byte
	spanIndex   int
	sourcePos   int64
	outputPos   int64
	replaceLeft int64
	tokenOffset int
	segmentHash hash.Hash
	replaceHash hash.Hash
	entries     []redaction.MappingEntry
	outputHash  hash.Hash
	done        bool
	terminalErr error
	utf8State   [4]byte
	utf8Count   int
	utf8Want    int
	utf8Invalid bool
}

func newTransformStream(source *plaintextReader, plan redaction.ApprovedPlan,
	material RedactionRuleMaterial) *transformStream {
	mask := byte(0)
	if len(material.Mask) == 1 {
		mask = material.Mask[0]
	}
	return &transformStream{source: source, plan: plan, mask: mask, token: append([]byte(nil), material.Token...),
		entries: make([]redaction.MappingEntry, 0, len(plan.Spans)), outputHash: sha256.New()}
}

func (stream *transformStream) ReadContext(ctx context.Context, destination []byte) (int, error) {
	if stream.terminalErr != nil {
		return 0, stream.terminalErr
	}
	if stream.done {
		return 0, io.EOF
	}
	if len(destination) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(destination) {
		if err := contextError(ctx); err != nil {
			stream.fail(err)
			return written, err
		}
		if stream.replaceLeft > 0 {
			count := stream.emitReplacement(destination[written:])
			written += count
			if stream.replaceLeft == 0 {
				stream.finishSpan()
			}
			continue
		}
		if stream.spanIndex < len(stream.plan.Spans) {
			span := stream.plan.Spans[stream.spanIndex]
			if stream.sourcePos < span.SourceStart {
				count := minInt64(int64(len(destination)-written), span.SourceStart-stream.sourcePos)
				if err := readSourceExact(ctx, stream.source, destination[written:written+int(count)]); err != nil {
					stream.fail(err)
					return written, err
				}
				stream.emitSource(destination[written : written+int(count)])
				written += int(count)
				continue
			}
			if err := stream.consumeSpan(ctx, span); err != nil {
				stream.fail(err)
				return written, err
			}
			if stream.replaceLeft == 0 {
				stream.finishSpan()
			}
			continue
		}
		if stream.sourcePos < stream.plan.Source.Artifact.Length {
			count := minInt64(int64(len(destination)-written), stream.plan.Source.Artifact.Length-stream.sourcePos)
			if err := readSourceExact(ctx, stream.source, destination[written:written+int(count)]); err != nil {
				stream.fail(err)
				return written, err
			}
			stream.emitSource(destination[written : written+int(count)])
			written += int(count)
			continue
		}
		if err := stream.finishSource(ctx); err != nil {
			stream.fail(err)
			return written, err
		}
		stream.done = true
		if written == 0 {
			return 0, io.EOF
		}
		return written, nil
	}
	return written, nil
}

func (stream *transformStream) consumeSpan(ctx context.Context, span redaction.PlanSpan) error {
	stream.segmentHash, stream.replaceHash = sha256.New(), sha256.New()
	remaining := span.SourceEnd - span.SourceStart
	buffer := make([]byte, 64*1024)
	defer zero(buffer)
	for remaining > 0 {
		count := minInt64(int64(len(buffer)), remaining)
		if err := readSourceExact(ctx, stream.source, buffer[:count]); err != nil {
			return err
		}
		stream.segmentHash.Write(buffer[:count])
		stream.sourcePos += count
		remaining -= count
	}
	if digestHash(stream.segmentHash) != span.SourceSegmentDigest {
		return newError(Denied, "redaction_segment_digest_mismatch", nil)
	}
	switch span.ReplacementMode {
	case redaction.Remove:
		stream.replaceLeft = 0
	case redaction.Mask:
		stream.replaceLeft = span.SourceEnd - span.SourceStart
	case redaction.Token:
		stream.replaceLeft = int64(len(stream.token))
		stream.tokenOffset = 0
	default:
		return newError(Denied, "redaction_replacement_mode_invalid", nil)
	}
	if stream.outputPos != span.ExpectedOutputStart || stream.outputPos+stream.replaceLeft != span.ExpectedOutputEnd {
		return newError(Denied, "redaction_output_interval_mismatch", nil)
	}
	return nil
}

func (stream *transformStream) emitReplacement(destination []byte) int {
	count := int(minInt64(int64(len(destination)), stream.replaceLeft))
	span := stream.plan.Spans[stream.spanIndex]
	if span.ReplacementMode == redaction.Mask {
		for index := 0; index < count; index++ {
			destination[index] = stream.mask
		}
	} else {
		copy(destination[:count], stream.token[stream.tokenOffset:stream.tokenOffset+count])
		stream.tokenOffset += count
	}
	stream.replaceHash.Write(destination[:count])
	stream.outputHash.Write(destination[:count])
	stream.validateOutput(destination[:count])
	stream.outputPos += int64(count)
	stream.replaceLeft -= int64(count)
	return count
}

func (stream *transformStream) emitSource(value []byte) {
	stream.outputHash.Write(value)
	stream.validateOutput(value)
	stream.sourcePos += int64(len(value))
	stream.outputPos += int64(len(value))
}

func (stream *transformStream) finishSpan() {
	span := stream.plan.Spans[stream.spanIndex]
	stream.entries = append(stream.entries, redaction.MappingEntry{Ordinal: span.Ordinal, SourceStart: span.SourceStart,
		SourceEnd: span.SourceEnd, SourceSegmentDigest: span.SourceSegmentDigest,
		OutputStart: span.ExpectedOutputStart, OutputEnd: span.ExpectedOutputEnd,
		ReplacementMode: span.ReplacementMode, ReplacementDigest: digestHash(stream.replaceHash)})
	stream.segmentHash, stream.replaceHash = nil, nil
	stream.spanIndex++
}

func (stream *transformStream) finishSource(ctx context.Context) error {
	var extra [1]byte
	count, err := stream.source.ReadContext(ctx, extra[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		return newError(Denied, "redaction_source_length_mismatch", err)
	}
	if stream.outputPos <= 0 || stream.outputPos > stream.plan.MaximumOutputBytes {
		return newError(Denied, "redaction_output_length_invalid", nil)
	}
	if stream.plan.OutputMediaType == "text/plain" && (stream.utf8Invalid || stream.utf8Count != 0) {
		return newError(Denied, "redaction_output_format_invalid", nil)
	}
	zero(stream.token)
	stream.token = nil
	return nil
}

func (stream *transformStream) validateOutput(value []byte) {
	if stream.plan.OutputMediaType != "text/plain" || stream.utf8Invalid {
		return
	}
	for _, octet := range value {
		if stream.utf8Count == 0 {
			switch {
			case octet < utf8.RuneSelf:
				continue
			case octet >= 0xc2 && octet <= 0xdf:
				stream.utf8Want = 2
			case octet >= 0xe0 && octet <= 0xef:
				stream.utf8Want = 3
			case octet >= 0xf0 && octet <= 0xf4:
				stream.utf8Want = 4
			default:
				stream.utf8Invalid = true
				return
			}
		}
		stream.utf8State[stream.utf8Count] = octet
		stream.utf8Count++
		if stream.utf8Count == stream.utf8Want {
			if !utf8.Valid(stream.utf8State[:stream.utf8Want]) {
				stream.utf8Invalid = true
				return
			}
			for index := range stream.utf8State {
				stream.utf8State[index] = 0
			}
			stream.utf8Count, stream.utf8Want = 0, 0
		}
	}
}

func (stream *transformStream) outputDigest() string { return digestHash(stream.outputHash) }
func (stream *transformStream) fail(err error) {
	stream.terminalErr = err
	stream.source.close()
	zero(stream.token)
	stream.token = nil
}

func (stream *transformStream) close() {
	if stream == nil {
		return
	}
	stream.source.close()
	zero(stream.token)
	stream.token = nil
	stream.done = true
}

func digestHash(value hash.Hash) string {
	if value == nil {
		sum := sha256.Sum256(nil)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return "sha256:" + hex.EncodeToString(value.Sum(nil))
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
