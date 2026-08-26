//go:build darwin || linux

package main

import (
	"fmt"
	"os"

	"github.com/ArronJablonowski/COH/internal/broker/nativeexecutor"
)

func main() {
	if err := nativeexecutor.RunLimitHelper(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(126)
	}
}
