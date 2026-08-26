package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "image":
		if len(os.Args) < 3 || os.Args[2] != "inspect" {
			os.Exit(2)
		}
		fmt.Printf("[%q]\n", os.Args[len(os.Args)-1])
	case "create":
		name := flagValue(os.Args[2:], "--name")
		if name == "" {
			os.Exit(2)
		}
		mode := os.Args[len(os.Args)-1]
		write(name+".mode", mode)
		write(name+".exit", "0 false")
		fmt.Println(name)
	case "start":
		name := os.Args[len(os.Args)-1]
		mode := read(name + ".mode")
		write(name+".started", "true")
		switch mode {
		case "health":
			return
		case "echo":
			_, _ = io.Copy(os.Stdout, os.Stdin)
		case "output":
			fmt.Print(strings.Repeat("x", 4096))
		case "sleep":
			for index := 0; index < 1000; index++ {
				if _, err := os.Stat(statePath(name + ".killed")); err == nil {
					write(name+".exit", "137 false")
					os.Exit(1)
				}
				time.Sleep(10 * time.Millisecond)
			}
		default:
			os.Exit(2)
		}
	case "inspect":
		name := os.Args[len(os.Args)-1]
		fmt.Println(read(name + ".exit"))
	case "kill":
		name := os.Args[len(os.Args)-1]
		write(name+".killed", "true")
	case "rm":
		name := os.Args[len(os.Args)-1]
		for _, suffix := range []string{".mode", ".exit", ".killed", ".started"} {
			_ = os.Remove(statePath(name + suffix))
		}
	default:
		os.Exit(2)
	}
}

func flagValue(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}

func statePath(name string) string { return filepath.Join(os.Getenv("HOME"), name) }

func write(name, value string) {
	if err := os.WriteFile(statePath(name), []byte(value), 0o600); err != nil {
		os.Exit(3)
	}
}

func read(name string) string {
	value, err := os.ReadFile(statePath(name))
	if err != nil {
		os.Exit(3)
	}
	return string(value)
}
