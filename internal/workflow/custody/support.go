package custody

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"
)

func deterministicUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func operationContext(parent context.Context, deadline, now time.Time) (context.Context, context.CancelFunc) {
	if existing, ok := parent.Deadline(); ok && existing.Before(deadline) {
		return context.WithDeadline(parent, existing)
	}
	if !deadline.After(now) {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}
	}
	return context.WithDeadline(parent, deadline)
}

func mapDependency(ctx context.Context, reason string, err error) error {
	if ctx != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return newError(Canceled, "request_canceled", false, context.Canceled)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return newError(Timeout, "request_timeout", false, context.DeadlineExceeded)
		}
	}
	switch CodeOf(err) {
	case Denied, NotFound, Conflict:
		return newError(CodeOf(err), Reason(err), Retryable(err), err)
	}
	return newError(Unavailable, reason, true, err)
}

func sortedDigests(values ...string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if digestPattern.MatchString(value) {
			unique[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
