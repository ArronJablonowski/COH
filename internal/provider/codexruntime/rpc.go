package codexruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type rpcServerResponse struct {
	ID     json.RawMessage `json:"id"`
	Result any             `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

func sendDocument(ctx context.Context, transport RPCTransport, value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(providercontract.Internal, "rpc_encoding", false)
	}
	canonical, err := canonicalJSON(encoded)
	if err != nil {
		return nil, err
	}
	if len(canonical) > maximumFrameBytes {
		return nil, newError(providercontract.Denied, "rpc_frame_too_large", false)
	}
	if err := transport.Send(ctx, canonical); err != nil {
		if ctx.Err() != nil {
			return nil, contextAdapterError(ctx.Err())
		}
		return nil, newError(providercontract.Unavailable, "rpc_send_failed", true)
	}
	return canonical, nil
}

func receiveDocument(ctx context.Context, transport RPCTransport) (inboundEnvelope, []byte, error) {
	raw, err := transport.Receive(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return inboundEnvelope{}, nil, contextAdapterError(ctx.Err())
		}
		if err == io.EOF {
			return inboundEnvelope{}, nil, newError(providercontract.Unavailable, "rpc_disconnected", true)
		}
		return inboundEnvelope{}, nil, newError(providercontract.Unavailable, "rpc_receive_failed", true)
	}
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return inboundEnvelope{}, nil, err
	}
	if len(canonical) > maximumFrameBytes {
		return inboundEnvelope{}, nil, newError(providercontract.Denied, "rpc_frame_too_large", false)
	}
	var envelope inboundEnvelope
	if err := decodeExact(canonical, &envelope); err != nil {
		return inboundEnvelope{}, nil, err
	}
	requestLike := envelope.Method != ""
	responseLike := len(envelope.Result) > 0 || len(envelope.Error) > 0
	if requestLike == responseLike || requestLike && len(envelope.Params) == 0 || responseLike && len(envelope.ID) == 0 {
		return inboundEnvelope{}, nil, newError(providercontract.InvalidInput, "rpc_envelope_shape", false)
	}
	return envelope, canonical, nil
}

func receiveResponseWithNotifications(ctx context.Context, transport RPCTransport, id uint64, output any, notify func(inboundEnvelope, []byte) error) ([][]byte, error) {
	documents := make([][]byte, 0, 2)
	for count := 0; count < 64; count++ {
		envelope, canonical, err := receiveDocument(ctx, transport)
		if err != nil {
			return nil, err
		}
		documents = append(documents, canonical)
		if envelope.Method != "" {
			if len(envelope.ID) > 0 {
				return nil, newError(providercontract.Conflict, "rpc_request_before_ready", false)
			}
			if notify == nil {
				return nil, newError(providercontract.Conflict, "rpc_notification_before_ready", false)
			}
			if err := notify(envelope, canonical); err != nil {
				return nil, err
			}
			continue
		}
		var received uint64
		if err := json.Unmarshal(envelope.ID, &received); err != nil || received != id {
			return nil, newError(providercontract.Conflict, "rpc_response_correlation", false)
		}
		if len(envelope.Error) > 0 && !bytes.Equal(bytes.TrimSpace(envelope.Error), []byte("null")) {
			var rpcErr rpcError
			if err := decodeExact(envelope.Error, &rpcErr); err != nil {
				return nil, err
			}
			return nil, newError(providercontract.Unavailable, "app_server_error", false)
		}
		if len(envelope.Result) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Result), []byte("null")) {
			return nil, newError(providercontract.InvalidInput, "rpc_result_missing", false)
		}
		if err := decodeExact(envelope.Result, output); err != nil {
			return nil, err
		}
		return documents, nil
	}
	return nil, newError(providercontract.Denied, "rpc_notification_flood", false)
}

func decodeParams(raw json.RawMessage, output any) error {
	if len(raw) == 0 {
		return newError(providercontract.InvalidInput, "rpc_params_missing", false)
	}
	return decodeExact(raw, output)
}

func validRPCID(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var number uint64
	if json.Unmarshal(raw, &number) == nil {
		return true
	}
	var text string
	return json.Unmarshal(raw, &text) == nil && validText(text, 128)
}
