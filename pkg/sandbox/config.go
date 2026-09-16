package sandbox

import (
	"time"
)

// Config defines the security and resource limits for a sandbox instance.
type Config struct {
	// ID is the unique identifier for the execution sandbox.
	ID string

	// MemoryLimitBytes specifies the hard cgroup memory ceiling.
	MemoryLimitBytes int64

	// MaxProcesses sets the pids.max limit to prevent fork bombs.
	MaxProcesses int64

	// Timeout specifies the maximum wall-clock duration the process can run.
	Timeout time.Duration

	// Command is the binary to execute (e.g., "/usr/bin/python3", "/bin/sh").
	Command string

	// Args contains the arguments passed to the command.
	Args []string

	// Env specifies environment variables passed to the sandboxed process.
	Env []string
}

// Result captures the outcome of the sandboxed execution.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
	TimedOut bool
}
