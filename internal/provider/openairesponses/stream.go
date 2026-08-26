package openairesponses

import (
	"bufio"
	"context"
	"encoding/json"
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
	streamContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := adapter.startRequest(streamContext, translation.wire, true)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	reducer := newStreamReducer(adapter, streamContext, request, requestValue, translation.tools, emit)
	if err := consumeSSE(response.Body, reducer); err != nil {
		return err
	}
	if !reducer.terminal {
		return newError(providercontract.Unavailable, "stream_terminal_missing", true)
	}
	return nil
}

func consumeSSE(reader io.Reader, reducer *streamReducer) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maximumResponseBytes)
	var eventName string
	dataLines := make([]string, 0, 1)
	total := 0
	flush := func() error {
		if len(dataLines) == 0 {
			eventName = ""
			return nil
		}
		data := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		if data == "[DONE]" {
			if !reducer.terminal {
				return newError(providercontract.Conflict, "stream_done_before_terminal", false)
			}
			eventName = ""
			return nil
		}
		canonical, err := canonicalJSON([]byte(data))
		if err != nil {
			return err
		}
		var header streamHeader
		if err := json.Unmarshal(canonical, &header); err != nil || header.Type == "" || eventName != "" && eventName != header.Type {
			return newError(providercontract.InvalidInput, "stream_event_header", false)
		}
		eventName = ""
		return reducer.consume(canonical, header)
	}
	for scanner.Scan() {
		line := scanner.Text()
		total += len(line) + 1
		if total > maximumResponseBytes {
			return newError(providercontract.Denied, "stream_too_large", false)
		}
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			return newError(providercontract.InvalidInput, "stream_sse_field", false)
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			if eventName != "" || value == "" {
				return newError(providercontract.Conflict, "stream_sse_event", false)
			}
			eventName = value
		case "data":
			dataLines = append(dataLines, value)
		default:
			return newError(providercontract.Unsupported, "stream_sse_field", false)
		}
	}
	if err := scanner.Err(); err != nil {
		return newError(providercontract.Unavailable, "stream_read_failed", true)
	}
	return flush()
}
