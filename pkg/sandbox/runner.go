package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// Runner orchestrates execution, enforcement, and I/O capturing.
type Runner struct {
	cfg Config
}

// NewRunner initializes a sandbox runner with a given configuration.
func NewRunner(cfg Config) *Runner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxProcesses == 0 {
		cfg.MaxProcesses = 64
	}
	if cfg.MemoryLimitBytes == 0 {
		cfg.MemoryLimitBytes = 128 * 1024 * 1024 // 128 MB default
	}

	return &Runner{cfg: cfg}
}

// Run executes the command inside Linux namespaces and a dedicated cgroup.
func (r *Runner) Run() (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()

	cg, err := NewCgroupController(r.cfg.ID)
	if err != nil {
		return nil, fmt.Errorf("cgroup init error: %w", err)
	}
	defer func() {
		_ = cg.Cleanup()
	}()

	if err := cg.ApplyLimits(r.cfg.MemoryLimitBytes, r.cfg.MaxProcesses); err != nil {
		return nil, fmt.Errorf("failed to apply cgroup limits: %w", err)
	}

	cmd := exec.CommandContext(ctx, r.cfg.Command, r.cfg.Args...)
	cmd.Env = r.cfg.Env

	// Drop privileges to unprivileged UID/GID 65534 (nobody:nogroup)
	const unprivilegedUID = 65534
	const unprivilegedGID = 65534

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNET,
		Credential: &syscall.Credential{
			Uid: unprivilegedUID,
			Gid: unprivilegedGID,
		},
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()

	// Start process asynchronously to bind to the cgroup immediately
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start process: %w", err)
	}

	if err := cg.AttachPID(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("failed to bind process to cgroup: %w", err)
	}

	waitErr := cmd.Wait()
	duration := time.Since(start)

	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	exitCode := 0

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if timedOut {
			exitCode = 124
		} else {
			return nil, fmt.Errorf("command execution failed: %w", waitErr)
		}
	}

	return &Result{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		Duration: duration,
		TimedOut: timedOut,
	}, nil
}