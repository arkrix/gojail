package sandbox

import (
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
	ID        string
	StorageMB int64
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdoutR   io.ReadCloser
	stderrR   io.ReadCloser
	cgroup    *CgroupController
	overlay   *OverlayManager
}

// Pool maintains a standby pool of warmed sandbox processes.
type Pool struct {
	mu             sync.Mutex
	capacity       int
	workers        chan *Worker
	closed         bool
	storageLimitMB int64
}

// NewPool initializes and prefills the warm worker pool with default 64MB storage.
func NewPool(capacity int) (*Pool, error) {
	return NewPoolWithStorage(capacity, 64)
}

// NewPoolWithStorage initializes the pool with a specific overlay storage quota.
func NewPoolWithStorage(capacity int, storageLimitMB int64) (*Pool, error) {
	if capacity <= 0 {
		capacity = 2
	}
	if storageLimitMB <= 0 {
		storageLimitMB = 64
	}

	p := &Pool{
		capacity:       capacity,
		workers:        make(chan *Worker, capacity),
		storageLimitMB: storageLimitMB,
	}

	for i := 0; i < capacity; i++ {
		w, err := p.spawnWorker(p.storageLimitMB)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("failed to prefill warm pool: %w", err)
		}
		p.workers <- w
	}

	return p, nil
}

// spawnWorker creates an isolated, pre-jailed child ready to accept commands.
func (p *Pool) spawnWorker(storageMB int64) (*Worker, error) {
	workerID := fmt.Sprintf("warm-%d", time.Now().UnixNano())

	// 1. Provision OverlayFS layer for this warm worker with explicit storage quota
	overlay, err := NewOverlayManager(workerID, storageMB)
	if err != nil {
		return nil, fmt.Errorf("overlay init error: %w", err)
	}

	targetRoot, err := overlay.Mount()
	if err != nil {
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("overlay mount error: %w", err)
	}

	// 2. Provision Cgroups v2
	cg, err := NewCgroupController(workerID)
	if err != nil {
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("cgroup init error: %w", err)
	}

	if err := cg.ApplyLimits(128*1024*1024, 64); err != nil {
		_ = cg.Cleanup()
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("failed to apply cgroup limits: %w", err)
	}

	selfBin, err := os.Executable()
	if err != nil {
		_ = cg.Cleanup()
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("failed to resolve binary path: %w", err)
	}

	cfg := Config{
		ID:             workerID,
		Command:        "/bin/sh",
		Args:           []string{"-s"},
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"},
		StorageLimitMB: storageMB,
		RootPath:       targetRoot,
	}

	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		_ = cg.Cleanup()
		_ = overlay.Cleanup()
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
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("failed to open stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinPipe.Close()
		_ = cg.Cleanup()
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("failed to open stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = stdinPipe.Close()
		_ = stdoutPipe.Close()
		_ = cg.Cleanup()
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("failed to open stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdinPipe.Close()
		_ = stdoutPipe.Close()
		_ = stderrPipe.Close()
		_ = cg.Cleanup()
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("failed to start warm worker: %w", err)
	}

	if err := cg.AttachPID(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = stdinPipe.Close()
		_ = stdoutPipe.Close()
		_ = stderrPipe.Close()
		_ = cg.Cleanup()
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("failed to attach warm worker to cgroup: %w", err)
	}

	if err := cg.Freeze(); err != nil {
		_ = cmd.Process.Kill()
		_ = stdinPipe.Close()
		_ = stdoutPipe.Close()
		_ = stderrPipe.Close()
		_ = cg.Cleanup()
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("failed to freeze warm worker: %w", err)
	}

	return &Worker{
		ID:        workerID,
		StorageMB: storageMB,
		cmd:       cmd,
		stdin:     stdinPipe,
		stdoutR:   stdoutPipe,
		stderrR:   stderrPipe,
		cgroup:    cg,
		overlay:   overlay,
	}, nil
}

// Acquire pulls an idle worker from the pool or spawns a fallback.
func (p *Pool) Acquire() (*Worker, error) {
	return p.AcquireWithStorage(p.storageLimitMB)
}

// AcquireWithStorage checks if a warm worker matches the requested storage; otherwise spawns a custom one.
func (p *Pool) AcquireWithStorage(requestedMB int64) (*Worker, error) {
	if requestedMB <= 0 {
		requestedMB = p.storageLimitMB
	}

	// If requested size matches the pool's default, pop from warm pool
	if requestedMB == p.storageLimitMB {
		select {
		case w := <-p.workers:
			go p.replenish()
			return w, nil
		default:
			return p.spawnWorker(requestedMB)
		}
	}

	// Dynamic custom storage quota: spawn custom worker on demand
	return p.spawnWorker(requestedMB)
}

func (p *Pool) replenish() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	w, err := p.spawnWorker(p.storageLimitMB)
	if err == nil {
		p.workers <- w
	}
}

// StreamHandler callbacks receive real-time stdout and stderr slices.
type StreamHandler struct {
	OnStdout func([]byte)
	OnStderr func([]byte)
}

// ExecuteStream streams process output in real-time and reports final metrics.
func (w *Worker) ExecuteStream(ctx context.Context, script string, handler StreamHandler) (*Result, error) {
	defer func() {
		_ = w.cgroup.Cleanup()
		_ = w.overlay.Cleanup()
	}()

	start := time.Now()

	if err := w.cgroup.Thaw(); err != nil {
		_ = w.cmd.Process.Kill()
		return nil, fmt.Errorf("failed to thaw worker cgroup: %w", err)
	}

	if _, err := io.WriteString(w.stdin, script+"\nexit\n"); err != nil {
		_ = w.cmd.Process.Kill()
		return nil, fmt.Errorf("failed to write payload to warm worker: %w", err)
	}
	_ = w.stdin.Close()

	var streamWG sync.WaitGroup

	// Real-time stdout streamer
	streamWG.Add(1)
	go func() {
		defer streamWG.Done()
		buf := make([]byte, 4096)
		for {
			n, rErr := w.stdoutR.Read(buf)
			if n > 0 && handler.OnStdout != nil {
				handler.OnStdout(buf[:n])
			}
			if rErr != nil {
				break
			}
		}
	}()

	// Real-time stderr streamer
	streamWG.Add(1)
	go func() {
		defer streamWG.Done()
		buf := make([]byte, 4096)
		for {
			n, rErr := w.stderrR.Read(buf)
			if n > 0 && handler.OnStderr != nil {
				handler.OnStderr(buf[:n])
			}
			if rErr != nil {
				break
			}
		}
	}()

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

	// Wait for pipe buffers to completely flush before exiting
	streamWG.Wait()

	duration := time.Since(start)
	metrics := w.cgroup.ReadMetrics()

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
		Duration: duration,
		TimedOut: timedOut,
		Metrics:  metrics,
	}, nil
}

// Close destroys all idle workers and frees cgroups and overlay mounts.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true
	close(p.workers)

	for w := range p.workers {
		_ = w.cgroup.Thaw()
		_ = w.cmd.Process.Kill()
		_ = w.cgroup.Cleanup()
		_ = w.overlay.Cleanup()
	}
}
