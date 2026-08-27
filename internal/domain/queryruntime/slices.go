package queryruntime

import (
	"context"
	"math/big"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var billion = big.NewInt(1_000_000_000)

// PlanSlices produces descriptors, not executable authority. Every derived
// query must be independently decoded, validated, and admitted.
func PlanSlices(ctx context.Context, query queryconnector.ValidatedQuery, decision querybounds.Decision,
	count uint32) (SlicePlan, error) {
	if err := contextError(ctx); err != nil {
		return SlicePlan{}, err
	}
	if query.Digest() == "" || count == 0 {
		return SlicePlan{}, newError(InvalidInput, "slice_request_invalid", nil)
	}
	if _, err := querybounds.VerifyDecision(decision); err != nil || decision.Outcome != "allowed" ||
		decision.QueryDigest != query.Digest() || decision.QueryID != query.Value().QueryID {
		return SlicePlan{}, newError(Denied, "slice_admission_invalid", err)
	}
	value := query.Value()
	if count > value.Limits.MaximumSlices || count > MaximumSliceDescriptors {
		return SlicePlan{}, newError(Denied, "slice_limit_exceeded", nil)
	}
	start, startErr := time.Parse(timestampLayout, value.TimeRange.Start)
	end, endErr := time.Parse(timestampLayout, value.TimeRange.End)
	if startErr != nil || endErr != nil || !start.Before(end) {
		return SlicePlan{}, newError(InvalidInput, "slice_interval_invalid", nil)
	}
	startNS := unixNanoseconds(start)
	endNS := unixNanoseconds(end)
	width := new(big.Int).Sub(endNS, startNS)
	if width.Sign() <= 0 || width.Cmp(new(big.Int).SetUint64(uint64(count))) < 0 {
		return SlicePlan{}, newError(Denied, "slice_interval_too_small", nil)
	}
	plan := SlicePlan{SchemaVersion: SlicePlanSchemaVersion, ContractVersion: ContractVersion,
		ParentQueryID: value.QueryID, ParentQueryDigest: query.Digest(), BoundsDecisionDigest: decision.DecisionDigest,
		Slices: make([]SliceDescriptor, 0, count)}
	divisor := new(big.Int).SetUint64(uint64(count))
	for index := uint32(0); index < count; index++ {
		left := proportionalBoundary(startNS, width, divisor, uint64(index))
		right := proportionalBoundary(startNS, width, divisor, uint64(index+1))
		descriptor := SliceDescriptor{Index: index + 1, Count: count,
			Start: fromUnixNanoseconds(left).Format(timestampLayout), End: fromUnixNanoseconds(right).Format(timestampLayout)}
		digestInput := struct {
			ParentQueryDigest    string `json:"parent_query_digest"`
			BoundsDecisionDigest string `json:"bounds_decision_digest"`
			Index                uint32 `json:"index"`
			Count                uint32 `json:"count"`
			Start                string `json:"start"`
			End                  string `json:"end"`
		}{query.Digest(), decision.DecisionDigest, descriptor.Index, count, descriptor.Start, descriptor.End}
		descriptor.SliceDigest, _ = canonicalDigest(sliceDigestDomain, digestInput)
		plan.Slices = append(plan.Slices, descriptor)
	}
	return finalizeSlicePlan(plan)
}

func unixNanoseconds(value time.Time) *big.Int {
	seconds := big.NewInt(value.Unix())
	return new(big.Int).Add(new(big.Int).Mul(seconds, billion), big.NewInt(int64(value.Nanosecond())))
}

func fromUnixNanoseconds(value *big.Int) time.Time {
	seconds, nanos := new(big.Int), new(big.Int)
	seconds.QuoRem(value, billion, nanos)
	if nanos.Sign() < 0 {
		seconds.Sub(seconds, big.NewInt(1))
		nanos.Add(nanos, billion)
	}
	return time.Unix(seconds.Int64(), nanos.Int64()).UTC()
}

func proportionalBoundary(start, width, divisor *big.Int, numerator uint64) *big.Int {
	offset := new(big.Int).Mul(width, new(big.Int).SetUint64(numerator))
	offset.Quo(offset, divisor)
	return new(big.Int).Add(start, offset)
}
