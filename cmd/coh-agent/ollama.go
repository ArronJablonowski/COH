package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/agentphase"
)

const ollamaEndpoint = "http://127.0.0.1:11434"

type ollamaGenerator struct {
	client    *http.Client
	model     string
	digest    string
	workspace string
	timeout   time.Duration
	think     any
}

type modelRecord struct {
	Name         string   `json:"name"`
	Model        string   `json:"model"`
	Digest       string   `json:"digest"`
	Capabilities []string `json:"capabilities"`
	Details      struct {
		Family string `json:"family"`
	} `json:"details"`
}

type tagResponse struct {
	Models []modelRecord `json:"models"`
}

type showResponse struct {
	Capabilities []string `json:"capabilities"`
	Details      struct {
		Family string `json:"family"`
	} `json:"details"`
	ModelInfo map[string]json.RawMessage `json:"model_info"`
}

type chatResponse struct {
	Model      string `json:"model"`
	Done       bool   `json:"done"`
	DoneReason string `json:"done_reason"`
	Message    struct {
		Role     string `json:"role"`
		Content  string `json:"content"`
		Thinking string `json:"thinking"`
	} `json:"message"`
	PromptEvalCount uint64 `json:"prompt_eval_count"`
	EvalCount       uint64 `json:"eval_count"`
	TotalDuration   uint64 `json:"total_duration"`
}

type fileChange struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type changeSet struct {
	Summary string       `json:"summary"`
	Files   []fileChange `json:"files"`
	Deletes []string     `json:"deletes"`
}

func newOllamaGenerator(ctx context.Context, model, expectedDigest, workspace string,
	timeout time.Duration) (*ollamaGenerator, agentphase.ModelExecutionProfile, error) {
	client := loopbackClient(timeout)
	var tags tagResponse
	if err := getJSON(ctx, client, "/api/tags", &tags); err != nil {
		return nil, agentphase.ModelExecutionProfile{}, fmt.Errorf("observe Ollama tags: %w", err)
	}
	var observed modelRecord
	for _, item := range tags.Models {
		if item.Name == model || item.Model == model {
			observed = item
			break
		}
	}
	if observed.Digest == "" || observed.Digest != expectedDigest {
		return nil, agentphase.ModelExecutionProfile{}, errors.New("frozen Ollama model digest mismatch")
	}
	var show showResponse
	if err := postJSON(ctx, client, "/api/show", map[string]any{"model": model, "verbose": true}, &show); err != nil {
		return nil, agentphase.ModelExecutionProfile{}, fmt.Errorf("observe Ollama model surface: %w", err)
	}
	if len(show.Capabilities) == 0 {
		return nil, agentphase.ModelExecutionProfile{}, errors.New("Ollama model did not advertise capabilities")
	}
	observed.Capabilities, observed.Details.Family = show.Capabilities, show.Details.Family
	capabilityDigest := digestJSON(struct {
		Record modelRecord  `json:"record"`
		Show   showResponse `json:"show"`
	}{observed, show})
	reasoningModes := []agentphase.ReasoningMode{agentphase.ReasoningDisabled}
	think := any(false)
	if contains(observed.Capabilities, "thinking") {
		if strings.Contains(strings.ToLower(observed.Details.Family), "gptoss") {
			reasoningModes, think = []agentphase.ReasoningMode{agentphase.ReasoningLow, agentphase.ReasoningMedium, agentphase.ReasoningHigh}, "low"
		} else {
			reasoningModes = []agentphase.ReasoningMode{agentphase.ReasoningDisabled, agentphase.ReasoningEnabled}
		}
	}
	toolCalls := contains(observed.Capabilities, "tools")
	profile, err := agentphase.QualifyExecutionProfile("ollama-local", agentphase.QualifiedModelSurface{
		ModelDigest: expectedDigest, CapabilityDigest: capabilityDigest,
		QualificationDigest: digestBytes([]byte("COH-OLLAMA-AGENT-QUALIFICATION-V1\x00" + expectedDigest + "\x00" + capabilityDigest)),
		MessageRoles:        []string{"system", "user", "assistant"}, ReasoningModes: reasoningModes,
		Text: contains(observed.Capabilities, "completion"), Vision: contains(observed.Capabilities, "vision"),
		ToolCalls: toolCalls, StructuredOutput: true, MaximumInputTokens: 32768,
		MaximumOutputTokens: 8192, MaximumParallelToolCall: boolLimit(toolCalls),
		SystemPrompt:  "You are COH, a precise cybersecurity operations agent. Produce completed, verifiable artifacts and preserve safety boundaries.",
		PromptOverlay: "Use the supplied workspace snapshot as evidence. Return only the requested structured change set; do not invent files you did not inspect.",
	})
	if err != nil {
		return nil, agentphase.ModelExecutionProfile{}, err
	}
	return &ollamaGenerator{client: client, model: model, digest: expectedDigest,
		workspace: workspace, timeout: timeout, think: think}, profile, nil
}

func (generator *ollamaGenerator) Generate(ctx context.Context,
	request agentphase.GenerationRequest) (agentphase.CandidateArtifact, string, error) {
	snapshot, err := snapshotWorkspace(generator.workspace)
	if err != nil {
		return agentphase.CandidateArtifact{}, "", err
	}
	prompt := request.UserPrompt + "\n\n<WORKSPACE_SNAPSHOT_UNTRUSTED>\n" + snapshot + "\n</WORKSPACE_SNAPSHOT_UNTRUSTED>\n"
	prompt += "Return a change set containing every file to create or replace. Paths must be relative to the workspace. Use deletes only when required."
	payload := map[string]any{"model": generator.model, "stream": false, "think": generator.think, "keep_alive": 0,
		"messages": []map[string]string{{"role": request.Profile.MessageRole, "content": request.Prompt.SystemPrompt}, {"role": "user", "content": prompt}},
		"format":   changeSetSchema(), "options": map[string]any{"num_ctx": request.Profile.MaximumInputTokens,
			"num_predict": request.Profile.MaximumOutputTokens, "temperature": 0, "top_p": 1, "seed": 42}}
	var response chatResponse
	if err = postJSON(ctx, generator.client, "/api/chat", payload, &response); err != nil {
		return agentphase.CandidateArtifact{}, "", fmt.Errorf("Ollama agent generation: %w", err)
	}
	if response.Model != generator.model || !response.Done || response.Message.Role != "assistant" ||
		(response.DoneReason != "stop" && response.DoneReason != "length") || response.PromptEvalCount == 0 || response.EvalCount == 0 {
		return agentphase.CandidateArtifact{}, "", errors.New("Ollama response identity, completion, or usage is invalid")
	}
	var changes changeSet
	decoder := json.NewDecoder(strings.NewReader(response.Message.Content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&changes); err != nil {
		return agentphase.CandidateArtifact{}, "", fmt.Errorf("decode model change set: %w", err)
	}
	if err = applyChangeSet(generator.workspace, changes); err != nil {
		return agentphase.CandidateArtifact{}, "", err
	}
	artifact, err := fingerprintWorkspace(generator.workspace)
	if err != nil {
		return agentphase.CandidateArtifact{}, "", err
	}
	budget := digestJSON(struct {
		Attempt      uint32 `json:"attempt"`
		InputTokens  uint64 `json:"input_tokens"`
		OutputTokens uint64 `json:"output_tokens"`
		Duration     uint64 `json:"duration"`
	}{request.Attempt, response.PromptEvalCount, response.EvalCount, response.TotalDuration})
	return agentphase.CandidateArtifact{ArtifactDigest: artifact, Text: changes.Summary,
		Workspace: generator.workspace, SideEffect: agentphase.SideEffectNone}, budget, nil
}

func loopbackClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != "127.0.0.1" || port != "11434" {
			return nil, errors.New("non-loopback Ollama route denied")
		}
		return dialer.DialContext(ctx, network, address)
	}}
	return &http.Client{Transport: transport, Timeout: timeout}
}

func getJSON(ctx context.Context, client *http.Client, path string, output any) error {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, ollamaEndpoint+path, nil)
	return executeJSON(client, request, output)
}

func postJSON(ctx context.Context, client *http.Client, path string, input, output any) error {
	encoded, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, ollamaEndpoint+path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	return executeJSON(client, request, output)
}

func executeJSON(client *http.Client, request *http.Request, output any) error {
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, output)
}

func digestJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return digestBytes(encoded)
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func boolLimit(enabled bool) uint16 {
	if enabled {
		return 1
	}
	return 0
}

func changeSetSchema() map[string]any {
	file := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"path", "content"},
		"properties": map[string]any{"path": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}}}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"summary", "files", "deletes"},
		"properties": map[string]any{"summary": map[string]any{"type": "string"},
			"files":   map[string]any{"type": "array", "maxItems": 64, "items": file},
			"deletes": map[string]any{"type": "array", "maxItems": 64, "items": map[string]any{"type": "string"}}}}
}
