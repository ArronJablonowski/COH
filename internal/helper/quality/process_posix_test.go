//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package quality

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCancellationReapsTermIgnoringGrandchild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", "-c", `trap '' TERM; sh -c 'trap "" TERM; echo $$; while :; do sleep 1; done'`)
	command.WaitDelay = 100 * time.Millisecond
	configureProcess(command)
	output, err := command.Output()
	if ctx.Err() == nil || err == nil {
		t.Fatalf("command err=%v context=%v", err, ctx.Err())
	}
	reapProcessGroup(command)
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(output)))
	if parseErr != nil {
		t.Fatalf("grandchild pid output=%q: %v", output, parseErr)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err = syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("TERM-ignoring grandchild %d survived group reap", pid)
}
