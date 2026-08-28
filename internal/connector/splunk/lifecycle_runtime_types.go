package splunk

import (
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type splunkExecutionFlight struct {
	done             chan struct{}
	validationDigest string
	expiresAt        time.Time
	execution        queryconnector.ValidatedExecution
	err              error
}

type splunkJobRecord struct {
	queryDigest      string
	validationDigest string
	query            queryconnector.Query
	plan             splunkparser.Plan
	execution        queryconnector.ValidatedExecution
	sid              string
	sidDigest        string
	dispatchReceipt  CallReceipt
	issuedAt         time.Time
	expiresAt        time.Time
	lastStatus       *JobStatus
	lastPoll         *queryconnector.ValidatedPoll
	lastPolledAt     time.Time
	rowsReturned     uint64
	bytesReturned    uint64
	pageNumber       uint32
	resultChain      string
	nextPage         *queryconnector.HandleRef
}

type splunkPollFlight struct {
	done   chan struct{}
	result queryconnector.ValidatedPoll
	err    error
}

type splunkPageRecord struct {
	handle      queryconnector.HandleRef
	jobHandleID string
	offset      uint64
	pageNumber  uint32
}

type splunkPageReplay struct {
	handle      queryconnector.HandleRef
	jobHandleID string
	queryID     string
	attemptID   string
	authority   queryconnector.AuthorityBinding
	page        queryconnector.ValidatedPage
}

type splunkPageFlight struct {
	done   chan struct{}
	result queryconnector.ValidatedPage
	err    error
}

type splunkCancellationFlight struct {
	done    chan struct{}
	request queryconnector.CancelRequest
	result  queryconnector.ValidatedCancellation
	err     error
}
