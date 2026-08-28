package codexruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func (a *Adapter) invokeBatch(ctx context.Context, validated providercontract.ValidatedRequest, request providercontract.InferenceRequest, translated translation) (providercontract.ValidatedResponse, error) {
	if len(translated.Tools) > 0 {
		return providercontract.ValidatedResponse{}, newError(providercontract.Unsupported, "batch_tools_not_supported", false)
	}
	started := a.config.Clock().UTC()
	argv := []string{"codex", "exec", "--json", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--strict-config",
		"-c", `web_search="disabled"`,
		"--disable", "shell_tool", "--disable", "unified_exec", "--disable", "multi_agent", "--disable", "tool_suggest",
		"--sandbox", "read-only", "--cd", a.config.Workspace, "--model", request.Provider.RequestedModel}
	if len(translated.OutputSchema) > 0 {
		argv = append(argv, "--output-schema", "/coh/runtime/output-schema.json")
	}
	argv = append(argv, "-")
	result, err := a.config.Batch.Run(ctx, BatchInvocation{Argv: argv, Environment: map[string]string{}, WorkingDirectory: a.config.Workspace, Stdin: []byte(translated.Prompt), OutputSchema: translated.OutputSchema, MaximumOutputBytes: maximumTraceBytes, Deadline: deadlineFromContext(ctx)})
	if err != nil {
		if ctx.Err() != nil {
			return providercontract.ValidatedResponse{}, contextAdapterError(ctx.Err())
		}
		return providercontract.ValidatedResponse{}, newError(providercontract.Unavailable, "batch_runner_failed", true)
	}
	if err := a.verifyObservation(request, result.Observation, "exec-jsonl"); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if result.ExitCode != 0 {
		return providercontract.ValidatedResponse{}, newError(providercontract.Unavailable, "batch_exit_failed", false)
	}
	if len(result.JSONL) == 0 || len(result.JSONL) > maximumTraceBytes || len(result.Stderr) > maximumTraceBytes {
		return providercontract.ValidatedResponse{}, newError(providercontract.Denied, "batch_output_size", false)
	}
	text, usage, err := parseExecJSONL(result.JSONL)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if err := a.validateUsage(request, usage); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	items := []providercontract.ContentItem{}
	if request.OutputConstraint.Kind == "json_schema" {
		canonical, err := canonicalJSON([]byte(text))
		if err != nil || !jsonObject(canonical) {
			return providercontract.ValidatedResponse{}, newError(providercontract.InvalidInput, "structured_output_invalid", false)
		}
		items = append(items, providercontract.ContentItem{Kind: "output_json", Value: canonical, SchemaDigest: request.OutputConstraint.SchemaDigest})
	} else {
		items = append(items, providercontract.ContentItem{Kind: "text", Text: text})
	}
	completed := a.config.Clock().UTC()
	if completed.IsZero() || completed.Before(started) {
		return providercontract.ValidatedResponse{}, newError(providercontract.Internal, "clock_invalid", false)
	}
	response := providercontract.InferenceResponse{SchemaVersion: providercontract.ResponseSchemaVersion, ContractVersion: providercontract.ContractVersion, ResponseID: deterministicUUID("COH-CODEX-EXEC-RESPONSE-ID-V1\x00", validated.Digest()+"\x00"+string(result.JSONL)), RequestID: request.RequestID, AttemptID: request.AttemptID, Provider: request.Provider, CapabilityDigest: request.CapabilityDigest, QualificationID: request.QualificationID, Outcome: "succeeded", Items: items, Usage: usage, State: providercontract.State{Mode: "stateless"}, StartedAt: formatTimestamp(started), CompletedAt: formatTimestamp(completed), ProvenanceDigest: digest("COH-CODEX-EXEC-TRACE-V1\x00", append([]byte(validated.Digest()+"\x00"), result.JSONL...))}
	encoded, _ := json.Marshal(response)
	out, err := providercontract.DecodeResponse(ctx, encoded)
	if err != nil {
		return providercontract.ValidatedResponse{}, newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	return out, nil
}

func parseExecJSONL(input []byte) (string, providercontract.Usage, error) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64<<10), maximumFrameBytes)
	started, turnStarted, completed := false, false, false
	threadID, final := "", ""
	var usage providercontract.Usage
	count := 0
	for scanner.Scan() {
		count++
		if count > maximumEvents {
			return "", usage, newError(providercontract.Denied, "event_limit", false)
		}
		canonical, err := canonicalJSON(scanner.Bytes())
		if err != nil {
			return "", usage, err
		}
		var event execEvent
		if err := decodeExact(canonical, &event); err != nil {
			return "", usage, err
		}
		switch event.Type {
		case "thread.started":
			if started || !validText(event.ThreadID, 128) {
				return "", usage, newError(providercontract.Conflict, "exec_thread", false)
			}
			started = true
			threadID = event.ThreadID
		case "turn.started":
			if !started || turnStarted {
				return "", usage, newError(providercontract.Conflict, "exec_turn", false)
			}
			turnStarted = true
		case "item.completed":
			if !turnStarted || event.Item == nil || event.Item.Type != "agent_message" || event.Item.Text == "" {
				return "", usage, newError(providercontract.Denied, "exec_item_not_supported", false)
			}
			final = event.Item.Text
		case "turn.completed":
			if !turnStarted || completed || event.Usage == nil {
				return "", usage, newError(providercontract.Conflict, "exec_terminal", false)
			}
			u := event.Usage
			if u.CachedInputTokens > u.InputTokens || u.CacheWriteInputTokens > u.InputTokens || u.ReasoningOutputTokens > u.OutputTokens {
				return "", usage, newError(providercontract.Denied, "usage_invalid", false)
			}
			usage = providercontract.Usage{InputTokens: u.InputTokens, OutputTokens: u.OutputTokens, TotalTokens: u.InputTokens + u.OutputTokens, CachedInputTokens: u.CachedInputTokens, ReasoningTokens: u.ReasoningOutputTokens}
			completed = true
		case "turn.failed", "error":
			return "", usage, newError(providercontract.Unavailable, "exec_turn_failed", false)
		default:
			return "", usage, newError(providercontract.Unsupported, "exec_event_not_supported", false)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", usage, newError(providercontract.Unavailable, "exec_stream_read", true)
	}
	if !started || threadID == "" || !turnStarted || !completed || final == "" {
		return "", usage, newError(providercontract.Conflict, "exec_terminal_missing", false)
	}
	return final, usage, nil
}

func deadlineFromContext(ctx context.Context) time.Time { value, _ := ctx.Deadline(); return value }
