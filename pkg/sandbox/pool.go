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

	"github.com/creack/pty"
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
	ptyMaster *os.File
}

// Cgroup returns the underlying CgroupController for metrics and telemetry sampling.
func (w *Worker) Cgroup() *CgroupController {
	return w.cgroup
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
		w, err := p.spawnWorker(p.storageLimitMB, nil, false, nil)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("failed to prefill warm pool: %w", err)
		}
		p.workers <- w
	}

	return p, nil
}

// spawnWorker creates an isolated, pre-jailed child ready to accept commands.
func (p *Pool) spawnWorker(storageMB int64, mounts []MountSpec, isTTY bool, initialCmd []string) (*Worker, error) {
	workerID := fmt.Sprintf("warm-%d", time.Now().UnixNano())

	overlay, err := NewOverlayManager(workerID, storageMB)
	if err != nil {
		return nil, fmt.Errorf("overlay init error: %w", err)
	}

	targetRoot, err := overlay.Mount()
	if err != nil {
		_ = overlay.Cleanup()
		return nil, fmt.Errorf("overlay mount error: %w", err)
	}

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

	targetCommand := "/bin/sh"
	targetArgs := []string{"-s"}
	if len(initialCmd) > 0 {
		targetCommand = initialCmd[0]
		if len(initialCmd) > 1 {
			targetArgs = initialCmd[1:]
		} else {
			targetArgs = []string{}
		}
	}

	cfg := Config{
		ID:             workerID,
		Command:        targetCommand,
		Args:           targetArgs,
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp", "TERM=xterm-256color"},
		StorageLimitMB: storageMB,
		RootPath:       targetRoot,
		Mounts:         mounts,
		TTY:            isTTY,
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

	// If interactive TTY requested, bind process to a pseudo-terminal pair
	if isTTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			_ = cg.Cleanup()
			_ = overlay.Cleanup()
			return nil, fmt.Errorf("failed to allocate pty: %w", err)
		}

		if err := cg.AttachPID(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = ptmx.Close()
			_ = cg.Cleanup()
			_ = overlay.Cleanup()
			return nil, fmt.Errorf("failed to attach pty process to cgroup: %w", err)
		}

		return &Worker{
			ID:        workerID,
			StorageMB: storageMB,
			cmd:       cmd,
			cgroup:    cg,
			overlay:   overlay,
			ptyMaster: ptmx,
		}, nil
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
	return p.AcquireCustom(p.storageLimitMB, nil, false, nil)
}

// AcquireWithStorage delegates to AcquireCustom with nil mounts and non-TTY.
func (p *Pool) AcquireWithStorage(requestedMB int64) (*Worker, error) {
	return p.AcquireCustom(requestedMB, nil, false, nil)
}

// AcquireCustom returns a warm worker if specs match defaults, or spawns an on-demand custom worker.
func (p *Pool) AcquireCustom(requestedMB int64, mounts []MountSpec, isTTY bool, cmd []string) (*Worker, error) {
	if requestedMB <= 0 {
		requestedMB = p.storageLimitMB
	}

	// Warm pool workers are batch / non-TTY with default storage and no custom mounts
	if !isTTY && len(mounts) == 0 && requestedMB == p.storageLimitMB {
		select {
		case w := <-p.workers:
			go p.replenish()
			return w, nil
		default:
			return p.spawnWorker(requestedMB, nil, false, nil)
		}
	}

	// Interactive TTY, custom mounts, or custom limits require an on-demand worker
	return p.spawnWorker(requestedMB, mounts, isTTY, cmd)
}

func (p *Pool) replenish() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	w, err := p.spawnWorker(p.storageLimitMB, nil, false, nil)
	if err == nil {
		p.workers <- w
	}
}

// StreamHandler callbacks receive real-time stdout and stderr slices.
type StreamHandler struct {
	OnStdout func([]byte)
	OnStderr func([]byte)
}

// PTYIOHandler manages bidirectional I/O for interactive terminal sessions.
type PTYIOHandler struct {
	OnOutput func([]byte)
}

// Resize sets the rows and columns on the master pseudo-terminal.
func (w *Worker) Resize(rows, cols uint16) error {
	if w.ptyMaster == nil {
		return errors.New("cannot resize non-pty worker")
	}
	return pty.Setsize(w.ptyMaster, &pty.Winsize{
		Rows: rows,
		Cols: cols,
	})
}

// WriteInput pushes client stdin bytes into the pseudo-terminal master.
func (w *Worker) WriteInput(data []byte) error {
	if w.ptyMaster == nil {
		return errors.New("cannot write input to non-pty worker")
	}
	_, err := w.ptyMaster.Write(data)
	return err
}

// ExecutePTY pumps interactive terminal I/O until the process terminates.
func (w *Worker) ExecutePTY(ctx context.Context, handler PTYIOHandler) (*Result, error) {
	defer func() {
		if w.ptyMaster != nil {
			_ = w.ptyMaster.Close()
		}
		_ = w.cgroup.Cleanup()
		_ = w.overlay.Cleanup()
	}()

	start := time.Now()

	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		buf := make([]byte, 4096)
		for {
			n, err := w.ptyMaster.Read(buf)
			if n > 0 && handler.OnOutput != nil {
				handler.OnOutput(buf[:n])
			}
			if err != nil {
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

	_ = w.ptyMaster.Close()
	<-outDone

	duration := time.Since(start)
	metrics := w.cgroup.ReadMetrics()

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if timedOut {
			exitCode = 124
		}
	}

	return &Result{
		ExitCode: exitCode,
		Duration: duration,
		TimedOut: timedOut,
		Metrics:  metrics,
	}, nil
}

// ExecuteStream streams batch process output in real-time and reports final metrics.
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
