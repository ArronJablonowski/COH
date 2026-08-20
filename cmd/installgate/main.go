// Command installgate applies the contained COH release lifecycle contract.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/supplychain"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "installgate: invalid_input")
		os.Exit(64)
	}
	timeout := 10 * time.Minute
	if value := os.Getenv("COH_INSTALL_TIMEOUT"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			fmt.Fprintln(os.Stderr, "installgate: invalid_input: timeout")
			os.Exit(64)
		}
		timeout = parsed
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, timeout)
	defer cancel()
	err := supplychain.RunLifecycle(ctx, os.Args[1], os.Args[2], os.Args[3], os.Args[4])
	if err == nil {
		fmt.Fprintf(os.Stdout, "release lifecycle %s: passed\n", os.Args[1])
		return
	}
	var typed *supplychain.Error
	if !errors.As(err, &typed) {
		fmt.Fprintln(os.Stderr, "installgate: tool_failure")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "installgate: %s: %s\n", typed.Code, typed.Field)
	if typed.Code == supplychain.CodeInvalidInput {
		os.Exit(64)
	}
	if typed.Code == supplychain.CodeTimeout || typed.Code == supplychain.CodeCanceled {
		os.Exit(1)
	}
	os.Exit(2)
}
