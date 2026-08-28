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
}

type splunkPollFlight struct {
	done   chan struct{}
	result queryconnector.ValidatedPoll
	err    error
}
