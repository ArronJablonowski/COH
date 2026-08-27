package securityonion

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type CallBinding struct {
	Scope     queryconnector.Scope
	Authority queryconnector.AuthorityBinding
	Operation string
	Targets   []string
}

type ClientCredential struct {
	ClientID string
	Secret   []byte
}

// CredentialSource lends one broker-owned client credential to the callback.
// Implementations must invalidate the slice immediately after the callback and
// return the immutable credential-lease decision digest.
type CredentialSource interface {
	Use(context.Context, CallBinding, func(ClientCredential) error) (string, error)
}

type CallReceipt struct {
	RequestDigest       string
	ResponseDigest      string
	LeaseDecisionDigest string
	TransportDigest     string
}

type InfoRequest struct {
	Binding       CallBinding
	Qualification ValidatedQualification
}

type InfoResult struct {
	Version        string
	ElasticVersion string
	ResultDigest   string
}

type EventQueryRequest struct {
	Binding       CallBinding
	Qualification ValidatedQualification
	Plan          ValidatedOQLPlan
}

type EventRecord struct {
	ID        string
	Timestamp string
	Payload   map[string]any
}

type MetricRecord struct {
	Keys  []string
	Value uint64
}

type EventQueryResult struct {
	Events        []EventRecord
	Metrics       []MetricRecord
	TotalEvents   uint64
	ElapsedMillis uint64
	EventCapHit   bool
	MetricCapHit  bool
	ResultDigest  string
}

type Client interface {
	Inspect(context.Context, InfoRequest) (InfoResult, CallReceipt, error)
	QueryEvents(context.Context, EventQueryRequest) (EventQueryResult, CallReceipt, error)
}
