package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(64)
	}
	switch os.Args[1] {
	case "echo":
		if _, err := io.Copy(os.Stdout, os.Stdin); err != nil {
			os.Exit(1)
		}
	case "environment":
		_, _ = fmt.Fprintln(os.Stdout, strings.Join(os.Environ(), "\n"))
	case "connect":
		connection, err := net.DialTimeout("tcp", os.Args[2], time.Second)
		if err == nil {
			_ = connection.Close()
			os.Exit(2)
		}
	case "write":
		if os.WriteFile(os.Args[2], []byte("escape"), 0o600) == nil {
			os.Exit(2)
		}
	case "output":
		length, _ := strconv.Atoi(os.Args[2])
		_, _ = os.Stdout.Write(make([]byte, length))
	case "sleep":
		time.Sleep(time.Hour)
	case "children":
		executable, _ := os.Executable()
		started := 0
		for index := 0; index < 3; index++ {
			command := exec.Command(executable, "sleep")
			command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := command.Start(); err == nil {
				started++
				defer command.Process.Kill()
			} else {
				_, _ = fmt.Fprintln(os.Stderr, err)
			}
		}
		if started == 0 {
			os.Exit(3)
		}
		time.Sleep(time.Hour)
	case "memory":
		data := make([]byte, 128<<20)
		for index := range data {
			data[index] = byte(index)
		}
		runtime.KeepAlive(data)
		time.Sleep(time.Hour)
	case "storage":
		for index := 0; index < 10; index++ {
			name := fmt.Sprintf("spill-%02d", index)
			if err := os.WriteFile(name, make([]byte, 32<<10), 0o600); err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				os.Exit(3)
			}
		}
		time.Sleep(time.Hour)
	default:
		os.Exit(64)
	}
}
