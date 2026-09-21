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
	"path/filepath"
	"syscall"
	"time"
)

// StreamHandler captures streaming stdout and stderr chunks in real time.
type StreamHandler struct {
	OnStdout func([]byte)
	OnStderr func([]byte)
}

// streamWriter adapts a chunk callback to an io.Writer.
type streamWriter struct {
	callback func([]byte)
}

func (sw *streamWriter) Write(p []byte) (int, error) {
	if sw.callback != nil && len(p) > 0 {
		cp := make([]byte, len(p))
		copy(cp, p)
		sw.callback(cp)
	}
	return len(p), nil
}

// Runner encapsulates the execution logic of an isolated process.
type Runner struct {
	cfg        Config
	cgroup     *CgroupController
	overlay    *OverlayFS
	cgroupRoot string
}

// NewRunner initializes a runner instance with the provided config.
func NewRunner(cfg Config) *Runner {
	return &Runner{
		cfg: cfg,
	}
}

// Run prepares isolation primitives, forks the child process, and enforces resource quotas.
func (r *Runner) Run() (*Result, error) {
	return r.runInternal(context.Background(), nil)
}

// RunContext executes the container within the cancellation boundary of an external context.
func (r *Runner) RunContext(ctx context.Context) (*Result, error) {
	return r.runInternal(ctx, nil)
}

// RunStream executes the container and dispatches output directly to streaming callbacks.
func (r *Runner) RunStream(ctx context.Context, handler StreamHandler) (*Result, error) {
	return r.runInternal(ctx, &handler)
}

func (r *Runner) runInternal(ctx context.Context, handler *StreamHandler) (*Result, error) {
	startTime := time.Now()

	cg, err := NewCgroupController(r.cfg.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cgroup: %w", err)
	}
	r.cgroup = cg
	defer func() {
		_ = r.cgroup.Cleanup()
	}()

	if err := r.cgroup.ApplyLimits(r.cfg.MemoryLimitBytes, r.cfg.MaxProcesses); err != nil {
		return nil, fmt.Errorf("failed to apply cgroup limits: %w", err)
	}

	storageLimit := r.cfg.StorageLimitMB
	if storageLimit <= 0 {
		storageLimit = 64
	}

	ovl, err := NewOverlayFSWithQuota(r.cfg.ID, storageLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create overlay scratch space: %w", err)
	}
	r.overlay = ovl
	defer func() {
		_ = r.overlay.Cleanup()
	}()

	r.cfg.RootFS = r.overlay.MergedDir

	for _, spec := range r.cfg.Mounts {
		if err := r.overlay.BindMount(spec); err != nil {
			return nil, fmt.Errorf("failed to configure bind mount %s:%s: %w", spec.Source, spec.Target, err)
		}
	}

	cfgData, err := json.Marshal(r.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize sandbox configuration: %w", err)
	}

	cmd := exec.Command("/proc/self/exe", "__init_child__", string(cfgData))

	var stdoutBuf, stderrBuf bytes.Buffer
	if handler != nil {
		cmd.Stdout = io.MultiWriter(&stdoutBuf, &streamWriter{callback: handler.OnStdout})
		cmd.Stderr = io.MultiWriter(&stderrBuf, &streamWriter{callback: handler.OnStderr})
	} else {
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNET,
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to fork sandbox process: %w", err)
	}

	pid := cmd.Process.Pid
	if err := r.cgroup.AttachPID(pid); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("failed to attach child to cgroup: %w", err)
	}

	timeout := r.cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var waitErr error
	timedOut := false

	select {
	case <-timeoutCtx.Done():
		timedOut = true
		_ = cmd.Process.Kill()
		waitErr = <-done
	case waitErr = <-done:
	}

	duration := time.Since(startTime)
	metrics := r.cgroup.ReadMetrics()

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return &Result{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		Duration: duration,
		TimedOut: timedOut,
		Metrics:  metrics,
	}, nil
}

// InitChild executes inside the newly created namespaces prior to running the target payload.
func InitChild(rawConfig string) error {
	var cfg Config
	if err := json.Unmarshal([]byte(rawConfig), &cfg); err != nil {
		return fmt.Errorf("child: failed to parse config payload: %w", err)
	}

	if err := syscall.Sethostname([]byte(cfg.ID)); err != nil {
		return fmt.Errorf("child: failed to set hostname: %w", err)
	}

	if err := syscall.Mount("", "/", "", syscall.MS_SLAVE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("child: failed to make root mount propagation slave: %w", err)
	}

	if err := mountBasicDevNodes(cfg.RootFS); err != nil {
		return fmt.Errorf("child: failed to mount dev nodes: %w", err)
	}

	if err := PivotRoot(cfg.RootFS); err != nil {
		return fmt.Errorf("child: pivot_root failed: %w", err)
	}

	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return fmt.Errorf("child: failed to mount isolated /proc: %w", err)
	}

	if err := ApplySeccompFilter(cfg.SeccompProfile); err != nil {
		return fmt.Errorf("child: failed to apply seccomp filter: %w", err)
	}

	if err := DropCapabilities(); err != nil {
		return fmt.Errorf("child: failed to drop capabilities: %w", err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("child: failed to chdir to root: %w", err)
	}

	binary, err := exec.LookPath(cfg.Command)
	if err != nil {
		return fmt.Errorf("child: command binary not found: %w", err)
	}

	args := append([]string{cfg.Command}, cfg.Args...)
	if err := syscall.Exec(binary, args, cfg.Env); err != nil {
		return fmt.Errorf("child: execve failed: %w", err)
	}

	return nil
}

// mountBasicDevNodes bind mounts standard Linux pseudo devices into the sandbox /dev root.
func mountBasicDevNodes(rootfs string) error {
	devDir := filepath.Join(rootfs, "dev")
	if err := os.MkdirAll(devDir, 0755); err != nil {
		return fmt.Errorf("failed to create /dev directory: %w", err)
	}

	ptsDir := filepath.Join(devDir, "pts")
	if err := os.MkdirAll(ptsDir, 0755); err != nil {
		return fmt.Errorf("failed to create /dev/pts: %w", err)
	}

	ptsOpts := "newinstance,ptmxmode=0666,mode=0620"
	_ = syscall.Mount("devpts", ptsDir, "devpts", syscall.MS_NOSUID|syscall.MS_NOEXEC, ptsOpts)

	nodes := []string{
		"null",
		"zero",
		"full",
		"random",
		"urandom",
		"tty",
	}

	for _, node := range nodes {
		hostPath := filepath.Join("/dev", node)
		targetPath := filepath.Join(devDir, node)

		if _, err := os.Stat(hostPath); err != nil {
			continue
		}

		if err := touchMountPoint(targetPath); err != nil {
			if node == "tty" {
				continue
			}
			return fmt.Errorf("failed to touch %s: %w", targetPath, err)
		}

		if err := syscall.Mount(hostPath, targetPath, "bind", syscall.MS_BIND, ""); err != nil {
			if node == "tty" {
				continue
			}
			return fmt.Errorf("failed to bind mount %s to %s: %w", hostPath, targetPath, err)
		}
	}

	_ = os.Symlink("/proc/self/fd", filepath.Join(devDir, "fd"))
	_ = os.Symlink("/proc/self/fd/0", filepath.Join(devDir, "stdin"))
	_ = os.Symlink("/proc/self/fd/1", filepath.Join(devDir, "stdout"))
	_ = os.Symlink("/proc/self/fd/2", filepath.Join(devDir, "stderr"))

	return nil
}

// touchMountPoint ensures a target regular file anchor exists without opening device drivers.
func touchMountPoint(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	return f.Close()
}
