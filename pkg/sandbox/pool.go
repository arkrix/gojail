package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Worker represents a pre-initialized sandbox worker waiting for input.
type Worker struct {
	ID     string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	cgroup *CgroupController
}

// Pool maintains a standby pool of warmed sandbox processes.
type Pool struct {
	mu       sync.Mutex
	capacity int
	workers  chan *Worker
	closed   bool
}

// NewPool initializes and prefills the warm worker pool.
func NewPool(capacity int) (*Pool, error) {
	if capacity <= 0 {
		capacity = 2
	}

	p := &Pool{
		capacity: capacity,
		workers:  make(chan *Worker, capacity),
	}

	for i := 0; i < capacity; i++ {
		w, err := p.spawnWorker()
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("failed to prefill warm pool: %w", err)
		}
		p.workers <- w
	}

	return p, nil
}

// spawnWorker creates an isolated, pre-jailed child ready to accept commands.
func (p *Pool) spawnWorker() (*Worker, error) {
	workerID := fmt.Sprintf("warm-%d", time.Now().UnixNano())

	cg, err := NewCgroupController(workerID)
	if err != nil {
		return nil, fmt.Errorf("cgroup init error: %w", err)
	}

	if err := cg.ApplyLimits(128*1024*1024, 64); err != nil {
		_ = cg.Cleanup()
		return nil, fmt.Errorf("failed to apply cgroup limits: %w", err)
	}

	selfBin, err := os.Executable()
	if err != nil {
		_ = cg.Cleanup()
		return nil, fmt.Errorf("failed to resolve binary path: %w", err)
	}

	cfg := Config{
		ID:      workerID,
		Command: "/bin/sh",
		Args:    []string{"-s"}, // Read instructions from stdin
		Env:     []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"},
	}

	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		_ = cg.Cleanup()
		return nil, fmt.Errorf("failed to marshal worker config: %w", err)
	}

	cmd := exec.Command(selfBin, "__init_child__", string(cfgBytes))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNET,
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		_ = cg.Cleanup()
		return nil, fmt.Errorf("failed to open stdin pipe: %w", err)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		_ = stdinPipe.Close()
		_ = cg.Cleanup()
		return nil, fmt.Errorf("failed to start warm worker: %w", err)
	}

	if err := cg.AttachPID(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = stdinPipe.Close()
		_ = cg.Cleanup()
		return nil, fmt.Errorf("failed to attach warm worker to cgroup: %w", err)
	}

	return &Worker{
		ID:     workerID,
		cmd:    cmd,
		stdin:  stdinPipe,
		stdout: &stdoutBuf,
		stderr: &stderrBuf,
		cgroup: cg,
	}, nil
}

// Acquire pulls an idle worker from the pool or spawns a fallback.
func (p *Pool) Acquire() (*Worker, error) {
	select {
	case w := <-p.workers:
		// Replenish the pool asynchronously
		go p.replenish()
		return w, nil
	default:
		// Pool exhausted; spawn on demand
		return p.spawnWorker()
	}
}

func (p *Pool) replenish() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	w, err := p.spawnWorker()
	if err == nil {
		p.workers <- w
	}
}

// Execute runs the command inside the warmed worker.
func (w *Worker) Execute(ctx context.Context, script string) (*Result, error) {
	defer func() {
		_ = w.cgroup.Cleanup()
	}()

	start := time.Now()

	// Feed payload into the warm shell and close stdin to signal execution end
	if _, err := io.WriteString(w.stdin, script+"\nexit\n"); err != nil {
		_ = w.cmd.Process.Kill()
		return nil, fmt.Errorf("failed to write payload to warm worker: %w", err)
	}
	_ = w.stdin.Close()

	done := make(chan error, 1)
	go func() {
		done <- w.cmd.Wait()
	}()

	var waitErr error
	timedOut := false

	select {
	case <-ctx.Done():
		_ = w.cmd.Process.Kill()
		timedOut = true
		waitErr = ctx.Err()
	case waitErr = <-done:
	}

	duration := time.Since(start)
	exitCode := 0

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if timedOut {
			exitCode = 124
		} else {
			return nil, fmt.Errorf("worker execution error: %w", waitErr)
		}
	}

	return &Result{
		ExitCode: exitCode,
		Stdout:   w.stdout.String(),
		Stderr:   w.stderr.String(),
		Duration: duration,
		TimedOut: timedOut,
	}, nil
}

// Close destroys all idle workers and frees cgroups.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true
	close(p.workers)

	for w := range p.workers {
		_ = w.cmd.Process.Kill()
		_ = w.cgroup.Cleanup()
	}
}
