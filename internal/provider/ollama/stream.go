package ollama

import (
	"bufio"
	"context"
	"io"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type StreamEmitter func(providercontract.ValidatedStreamEvent) error

func (adapter *Adapter) Stream(ctx context.Context, request providercontract.ValidatedRequest, emit StreamEmitter) error {
	requestValue, timeout, err := adapter.validateDispatch(ctx, request)
	if err != nil {
		return err
	}
	if emit == nil {
		return newError(providercontract.InvalidInput, "stream_emitter_required", false)
	}
	translation, err := adapter.translateRequest(ctx, requestValue)
	if err != nil {
		return err
	}
	translation.wire.Stream = true
	streamContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	reducer := newStreamReducer(adapter, streamContext, request, requestValue, translation.tools, emit)
	if err := adapter.verifyIdentity(streamContext, requestValue.Provider.RequestedModel); err != nil {
		return reducer.finishAdapterError(err)
	}
	response, err := adapter.startRequest(streamContext, "POST", ChatPath, translation.wire, "application/x-ndjson")
	if err != nil {
		return reducer.finishAdapterError(err)
	}
	defer response.Body.Close()
	if err := consumeNDJSON(response.Body, reducer); err != nil {
		if !reducer.terminal && (Code(err) == providercontract.Canceled || Code(err) == providercontract.Timeout ||
			Code(err) == providercontract.Unavailable) {
			return reducer.finishAdapterError(err)
		}
		return err
	}
	if !reducer.terminal {
		return reducer.finishAdapterError(newError(providercontract.Unavailable, "stream_terminal_missing", true))
	}
	return nil
}

func consumeNDJSON(reader io.Reader, reducer *streamReducer) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maximumResponseBytes)
	total := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		total += len(line) + 1
		if total > maximumResponseBytes {
			return newError(providercontract.Denied, "stream_too_large", false)
		}
		if len(line) == 0 {
			return newError(providercontract.InvalidInput, "stream_empty_record", false)
		}
		canonical, err := canonicalJSON(line)
		if err != nil {
			return err
		}
		var chunk chatResponse
		if err := decodeExact(canonical, &chunk); err != nil {
			return err
		}
		if err := reducer.consume(canonical, chunk); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return newError(providercontract.Unavailable, "stream_read_failed", true)
	}
	return nil
}
