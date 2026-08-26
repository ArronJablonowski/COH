//go:build darwin || linux

package nativeexecutor

import (
	"errors"
	"math"
	"syscall"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

func applyPlatformIsolation(limits toolregistry.ResourceLimits) error {
	cpuSeconds := (limits.CPUMilliseconds + 999) / 1000
	values := []struct {
		name     string
		resource int
		value    uint64
	}{
		{"cpu", syscall.RLIMIT_CPU, cpuSeconds},
		{"file", syscall.RLIMIT_FSIZE, limits.EphemeralStorageBytes},
		{"open_file", syscall.RLIMIT_NOFILE, uint64(limits.OpenFileCount)},
		{"core", syscall.RLIMIT_CORE, 0},
	}
	for _, item := range values {
		if item.value > math.MaxInt64 {
			return NewError(InvalidInput, "resource_limits")
		}
		limit := &syscall.Rlimit{Cur: item.value, Max: item.value}
		if err := syscall.Setrlimit(item.resource, limit); err != nil {
			return NewError(Denied, "resource_limit_"+item.name+"_unavailable")
		}
	}
	return nil
}

func replaceProcess(path string, arguments, environment []string) error {
	if err := syscall.Exec(path, arguments, environment); err != nil {
		return errors.Join(NewError(Unavailable, "process_exec_failed"), err)
	}
	return nil
}
