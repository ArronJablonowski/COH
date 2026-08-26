package openairesponses

import "encoding/json"

type streamHeader struct {
	Type           string `json:"type"`
	SequenceNumber uint64 `json:"sequence_number"`
}

type streamResponseEvent struct {
	Type           string         `json:"type"`
	SequenceNumber uint64         `json:"sequence_number"`
	Response       createResponse `json:"response"`
}

type streamItemEvent struct {
	Type           string          `json:"type"`
	OutputIndex    uint64          `json:"output_index"`
	Item           json.RawMessage `json:"item"`
	SequenceNumber uint64          `json:"sequence_number"`
}

type streamContentEvent struct {
	Type           string          `json:"type"`
	ItemID         string          `json:"item_id"`
	OutputIndex    uint64          `json:"output_index"`
	ContentIndex   uint64          `json:"content_index"`
	Part           json.RawMessage `json:"part"`
	SequenceNumber uint64          `json:"sequence_number"`
}

type streamTextDelta struct {
	Type           string            `json:"type"`
	ItemID         string            `json:"item_id"`
	OutputIndex    uint64            `json:"output_index"`
	ContentIndex   uint64            `json:"content_index"`
	Delta          string            `json:"delta"`
	Logprobs       []json.RawMessage `json:"logprobs"`
	SequenceNumber uint64            `json:"sequence_number"`
}

type streamTextDone struct {
	Type           string            `json:"type"`
	ItemID         string            `json:"item_id"`
	OutputIndex    uint64            `json:"output_index"`
	ContentIndex   uint64            `json:"content_index"`
	Text           string            `json:"text"`
	Logprobs       []json.RawMessage `json:"logprobs"`
	SequenceNumber uint64            `json:"sequence_number"`
}

type streamFunctionDelta struct {
	Type           string `json:"type"`
	ItemID         string `json:"item_id"`
	OutputIndex    uint64 `json:"output_index"`
	Delta          string `json:"delta"`
	SequenceNumber uint64 `json:"sequence_number"`
}

type streamFunctionDone struct {
	Type           string `json:"type"`
	ItemID         string `json:"item_id"`
	OutputIndex    uint64 `json:"output_index"`
	Name           string `json:"name"`
	Arguments      string `json:"arguments"`
	SequenceNumber uint64 `json:"sequence_number"`
}

type streamSummaryDelta struct {
	Type           string `json:"type"`
	ItemID         string `json:"item_id"`
	OutputIndex    uint64 `json:"output_index"`
	SummaryIndex   uint64 `json:"summary_index"`
	Delta          string `json:"delta"`
	SequenceNumber uint64 `json:"sequence_number"`
}

type streamSummaryPartEvent struct {
	Type           string          `json:"type"`
	ItemID         string          `json:"item_id"`
	OutputIndex    uint64          `json:"output_index"`
	SummaryIndex   uint64          `json:"summary_index"`
	Part           json.RawMessage `json:"part"`
	SequenceNumber uint64          `json:"sequence_number"`
}

type streamSummaryDone struct {
	Type           string `json:"type"`
	ItemID         string `json:"item_id"`
	OutputIndex    uint64 `json:"output_index"`
	SummaryIndex   uint64 `json:"summary_index"`
	Text           string `json:"text"`
	SequenceNumber uint64 `json:"sequence_number"`
}

type streamRefusalDelta struct {
	Type           string `json:"type"`
	ItemID         string `json:"item_id"`
	OutputIndex    uint64 `json:"output_index"`
	ContentIndex   uint64 `json:"content_index"`
	Delta          string `json:"delta"`
	SequenceNumber uint64 `json:"sequence_number"`
}

type streamRefusalDone struct {
	Type           string `json:"type"`
	ItemID         string `json:"item_id"`
	OutputIndex    uint64 `json:"output_index"`
	ContentIndex   uint64 `json:"content_index"`
	Refusal        string `json:"refusal"`
	SequenceNumber uint64 `json:"sequence_number"`
}

type streamError struct {
	Type           string  `json:"type"`
	Code           *string `json:"code"`
	Message        string  `json:"message"`
	Param          *string `json:"param"`
	SequenceNumber uint64  `json:"sequence_number"`
}
