package llamacpp

import (
	"bufio"
	"context"
	"io"
	"strings"

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
	translation.wire.StreamOptions = &streamOptions{IncludeUsage: true}
	streamContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	reducer := newStreamReducer(adapter, streamContext, request, requestValue, translation.tools, emit)
	if err := adapter.verifyIdentity(streamContext, requestValue.Provider.RequestedModel); err != nil {
		return reducer.finishAdapterError(err)
	}
	response, err := adapter.startRequest(streamContext, "POST", ChatPath, translation.wire, "text/event-stream")
	if err != nil {
		return reducer.finishAdapterError(err)
	}
	defer response.Body.Close()
	if err := consumeSSE(response.Body, reducer); err != nil {
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

func consumeSSE(reader io.Reader, reducer *streamReducer) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maximumResponseBytes)
	total, awaitingSeparator := 0, false
	for scanner.Scan() {
		line := scanner.Text()
		total += len(line) + 1
		if total > maximumResponseBytes {
			return newError(providercontract.Denied, "stream_too_large", false)
		}
		if line == "" {
			if !awaitingSeparator {
				return newError(providercontract.InvalidInput, "stream_empty_event", false)
			}
			awaitingSeparator = false
			continue
		}
		if awaitingSeparator || !strings.HasPrefix(line, "data: ") {
			return newError(providercontract.InvalidInput, "stream_frame_invalid", false)
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			if err := reducer.finishDone(); err != nil {
				return err
			}
		} else {
			canonical, err := canonicalJSON([]byte(data))
			if err != nil {
				return err
			}
			var chunk streamChunk
			if err := decodeExact(canonical, &chunk); err != nil {
				return err
			}
			if err := reducer.consume(canonical, chunk); err != nil {
				return err
			}
		}
		awaitingSeparator = true
	}
	if err := scanner.Err(); err != nil {
		return newError(providercontract.Unavailable, "stream_read_failed", true)
	}
	if awaitingSeparator && !reducer.terminal {
		return newError(providercontract.InvalidInput, "stream_separator_missing", false)
	}
	return nil
}
