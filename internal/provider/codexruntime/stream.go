package codexruntime

import (
	"context"
	"encoding/json"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type StreamEmitter func(providercontract.ValidatedStreamEvent) error

func (a *Adapter) Stream(ctx context.Context, request providercontract.ValidatedRequest, emit StreamEmitter) error {
	v, timeout, err := a.validateDispatch(ctx, request)
	if err != nil {
		return err
	}
	if emit == nil {
		return newError(providercontract.InvalidInput, "stream_emitter_required", false)
	}
	translated, err := a.translateRequest(ctx, v)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sequence := uint64(0)
	emitValue := func(event providercontract.StreamEvent) error {
		event.SchemaVersion = providercontract.StreamEventSchemaVersion
		event.ContractVersion = providercontract.ContractVersion
		event.RequestID = v.RequestID
		event.AttemptID = v.AttemptID
		event.Sequence = sequence
		event.ObservedAt = formatTimestamp(a.config.Clock())
		encoded, _ := json.Marshal(event)
		decodeCtx := runCtx
		if event.Kind == "error" {
			decodeCtx = context.WithoutCancel(runCtx)
		}
		validated, decodeErr := providercontract.DecodeStreamEvent(decodeCtx, encoded)
		if decodeErr != nil {
			return newError(providercontract.Code(decodeErr), providercontract.Reason(decodeErr), false)
		}
		if emitErr := emit(validated); emitErr != nil {
			return newError(providercontract.Unavailable, "stream_emitter_failed", false)
		}
		sequence++
		return nil
	}
	var response providercontract.ValidatedResponse
	if v.Provider.RuntimeName == "codex-exec" {
		response, err = a.invokeBatch(runCtx, request, v, translated)
	} else {
		response, err = a.invokeAppServer(runCtx, request, v, translated, func(delta string) error {
			return emitValue(providercontract.StreamEvent{Kind: "text_delta", TextDelta: delta})
		})
	}
	if err != nil {
		terminal := providercontract.TerminalError{Code: string(Code(err)), Reason: Reason(err), Message: "Codex runtime stream failed", Retryable: Retryable(err)}
		if Code(err) == providercontract.Canceled {
			terminal.Message = "Codex runtime stream was canceled"
		} else if Code(err) == providercontract.Timeout {
			terminal.Message = "Codex runtime stream timed out"
		}
		return emitValue(providercontract.StreamEvent{Kind: "error", Error: &terminal})
	}
	value := response.Value()
	for _, item := range value.Items {
		copy := item
		if err := emitValue(providercontract.StreamEvent{Kind: "item", Item: &copy}); err != nil {
			return err
		}
	}
	return emitValue(providercontract.StreamEvent{Kind: "completed", Response: &value})
}
