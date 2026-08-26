//go:build darwin || linux

package nativeexecutor

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func monitorMemory(ctx context.Context, process *os.Process, limit uint64,
	exceeded, failed chan<- struct{}, done <-chan struct{}) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			resident, err := residentBytes(process.Pid)
			if err != nil {
				if !processAlive(process) {
					return
				}
				signalMonitor(failed)
				_ = killProcessGroup(process)
				return
			}
			if resident > limit {
				signalMonitor(exceeded)
				_ = killProcessGroup(process)
				return
			}
		}
	}
}

func monitorProcessCount(ctx context.Context, process *os.Process, limit uint16,
	exceeded, failed chan<- struct{}, done <-chan struct{}) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			count, err := processTreeCount(process.Pid)
			if err != nil {
				if !processAlive(process) {
					return
				}
				signalMonitor(failed)
				_ = killProcessGroup(process)
				return
			}
			if count > uint64(limit) {
				signalMonitor(exceeded)
				_ = killProcessGroup(process)
				return
			}
		}
	}
}

func monitorStorage(ctx context.Context, root string, limit uint64, process *os.Process,
	exceeded, failed chan<- struct{}, done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			used, err := directoryBytes(root)
			if err != nil {
				signalMonitor(failed)
				_ = killProcessGroup(process)
				return
			}
			if used > limit {
				signalMonitor(exceeded)
				_ = killProcessGroup(process)
				return
			}
		}
	}
}

func residentBytes(pid int) (uint64, error) {
	command := exec.Command("/bin/ps", "-o", "rss=", "-p", strconv.Itoa(pid))
	command.Env = []string{"LANG=C"}
	data, err := command.Output()
	if err != nil {
		return 0, err
	}
	kibibytes, err := strconv.ParseUint(string(bytes.TrimSpace(data)), 10, 64)
	if err != nil {
		return 0, err
	}
	return kibibytes * 1024, nil
}

func processTreeCount(rootPID int) (uint64, error) {
	command := exec.Command("/bin/ps", "-axo", "pid=,ppid=")
	command.Env = []string{"LANG=C"}
	data, err := command.Output()
	if err != nil {
		return 0, err
	}
	children := make(map[int][]int)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) != 2 {
			continue
		}
		pid, pidErr := strconv.Atoi(string(fields[0]))
		parent, parentErr := strconv.Atoi(string(fields[1]))
		if pidErr == nil && parentErr == nil {
			children[parent] = append(children[parent], pid)
		}
	}
	queue := []int{rootPID}
	seen := make(map[int]bool)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		queue = append(queue, children[pid]...)
	}
	return uint64(len(seen)), nil
}

func directoryBytes(root string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.Size() > 0 {
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

func processAlive(process *os.Process) bool {
	if process == nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func signalMonitor(channel chan<- struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}
