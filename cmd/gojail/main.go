package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/arkrix/gojail/pkg/sandbox"
)

func main() {
	// Check if this execution is an internal re-exec child call
	if len(os.Args) > 2 && os.Args[1] == "__init_child__" {
		if err := sandbox.InitChild(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error in child init: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Standard CLI flag parsing
	cmdFlag := flag.String("cmd", "/bin/sh", "Command to execute")
	codeFlag := flag.String("c", "", "Inline command or script body")
	timeoutSec := flag.Int("timeout", 5, "Timeout in seconds")
	memMB := flag.Int64("mem", 128, "Memory ceiling in megabytes")
	flag.Parse()

	if *codeFlag == "" {
		fmt.Println("Error: must provide a command via -c flag")
		os.Exit(1)
	}

	sandboxID := fmt.Sprintf("jail-%d", time.Now().UnixNano())

	cfg := sandbox.Config{
		ID:               sandboxID,
		MemoryLimitBytes: *memMB * 1024 * 1024,
		MaxProcesses:     32,
		Timeout:          time.Duration(*timeoutSec) * time.Second,
		Command:          *cmdFlag,
		Args:             []string{"-c", *codeFlag},
		Env:              []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"},
	}

	runner := sandbox.NewRunner(cfg)

	fmt.Printf("[gojail] Launching sandbox %s...\n", sandboxID)
	res, err := runner.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gojail] Execution error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[gojail] Completed in %v (Exit Code: %d, TimedOut: %t)\n", res.Duration, res.ExitCode, res.TimedOut)
	if res.Stdout != "" {
		fmt.Printf("--- STDOUT ---\n%s", res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Printf("--- STDERR ---\n%s", res.Stderr)
	}

	os.Exit(res.ExitCode)
}