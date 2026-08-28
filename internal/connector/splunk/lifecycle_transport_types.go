package splunk

import "github.com/ArronJablonowski/COH/internal/connector/splunkparser"

type SearchCreateRequest struct {
	Binding CallBinding
	Plan    splunkparser.Plan
}

type SearchCreateResult struct {
	SID       string
	SIDDigest string
}

type SearchStatusRequest struct {
	Binding CallBinding
	SID     string
}

type SearchResultsRequest struct {
	Binding CallBinding
	SID     string
	Offset  uint64
	Count   uint32
	Total   uint64
	Plan    splunkparser.Plan
}

type SearchCancelRequest struct {
	Binding CallBinding
	SID     string
}

type SearchCancelResult struct {
	Acknowledged bool
}
