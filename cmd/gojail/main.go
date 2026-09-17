package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/arkrix/gojail/pkg/client"
	"github.com/arkrix/gojail/pkg/sandbox"
)

func main() {
	// 1. High-priority internal hook for containerized init process
	if len(os.Args) >= 3 && os.Args[1] == "__init_child__" {
		if err := sandbox.InitChild(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error in child init: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 2. Subcommand routing
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		handleRunCommand(os.Args[2:])
	case "direct":
		handleDirectCommand(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	default:
		// Fallback for direct invocations if legacy flag syntax is used
		handleDirectCommand(os.Args[1:])
	}
}

func handleRunCommand(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cmdFlag := fs.String("cmd", "/bin/sh", "Command binary to execute")
	codeFlag := fs.String("c", "", "Inline command or script body")
	timeoutSec := fs.Int("timeout", 5, "Execution timeout in seconds")
	memMB := fs.Int64("mem", 128, "Memory ceiling in megabytes")
	procsMax := fs.Int64("procs", 64, "Maximum allowed processes")
	socketPath := fs.String("socket", "/var/run/gojail.sock", "Path to gojaild socket")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Support both positional script syntax `gojail run "..."` and flag syntax `gojail run -c "..."`
	scriptBody := *codeFlag
	if scriptBody == "" && len(fs.Args()) > 0 {
		scriptBody = fs.Args()[0]
	}

	if scriptBody == "" {
		fmt.Println("Error: must provide a command body or script to execute")
		fmt.Println("Example: gojail run \"echo hello\"")
		os.Exit(1)
	}

	c := client.NewClient(*socketPath)

	opts := client.ExecOptions{
		Command:          *cmdFlag,
		Args:             []string{"-c", scriptBody},
		Timeout:          time.Duration(*timeoutSec) * time.Second,
		MemoryLimitBytes: *memMB * 1024 * 1024,
		MaxProcesses:     *procsMax,
	}

	resp, err := c.Run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gojail] Client error: %v\n", err)
		os.Exit(1)
	}

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "[gojail] Execution rejected: %s\n", resp.Error)
		os.Exit(1)
	}

	if resp.Stdout != "" {
		fmt.Print(resp.Stdout)
	}
	if resp.Stderr != "" {
		fmt.Fprint(os.Stderr, resp.Stderr)
	}

	if resp.TimedOut {
		fmt.Fprintf(os.Stderr, "[gojail] Execution timed out after %v\n", resp.Duration)
	}

	os.Exit(resp.ExitCode)
}

func handleDirectCommand(args []string) {
	fs := flag.NewFlagSet("direct", flag.ExitOnError)
	cmdFlag := fs.String("cmd", "/bin/sh", "Command binary to execute")
	codeFlag := fs.String("c", "", "Inline command or script body")
	timeoutSec := fs.Int("timeout", 5, "Timeout in seconds")
	memMB := fs.Int64("mem", 128, "Memory ceiling in megabytes")
	procsMax := fs.Int64("procs", 32, "Maximum allowed processes")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	scriptBody := *codeFlag
	if scriptBody == "" && len(fs.Args()) > 0 {
		scriptBody = fs.Args()[0]
	}

	if scriptBody == "" {
		fmt.Println("Error: must provide a command via -c flag or as an argument")
		os.Exit(1)
	}

	sandboxID := fmt.Sprintf("jail-%d", time.Now().UnixNano())
	cfg := sandbox.Config{
		ID:               sandboxID,
		MemoryLimitBytes: *memMB * 1024 * 1024,
		MaxProcesses:     *procsMax,
		Timeout:          time.Duration(*timeoutSec) * time.Second,
		Command:          *cmdFlag,
		Args:             []string{"-c", scriptBody},
		Env:              []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"},
	}

	runner := sandbox.NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gojail] Direct execution error: %v\n", err)
		os.Exit(1)
	}

	if res.Stdout != "" {
		fmt.Print(res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Fprint(os.Stderr, res.Stderr)
	}

	os.Exit(res.ExitCode)
}

func printUsage() {
	fmt.Println("Usage: gojail <command> [options] [script]")
	fmt.Println("\nCommands:")
	fmt.Println("  run      Execute command via the background daemon (gojaild)")
	fmt.Println("  direct   Execute command directly using root permissions (standalone mode)")
	fmt.Println("\nExamples:")
	fmt.Println("  gojail run \"echo 'Hello World'\"")
	fmt.Println("  gojail run -mem 256 -timeout 3 \"python3 -c 'print(1+1)'\"")
}
