package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// Run spawns a contained child process inside namespaces and cgroups.
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

	// Serialize configuration to pass to the internal init-child process
	cfgBytes, err := json.Marshal(r.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}

	// Re-execute the current executable with the hidden internal subcommand
	selfBin, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.CommandContext(ctx, selfBin, "__init_child__", string(cfgBytes))

	// Allocate new namespaces: Mount (NEWNS), PID, UTS, IPC, Network
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNET,
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start containerized child: %w", err)
	}

	// Attach the new child process to the cgroup immediately
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
			return nil, fmt.Errorf("execution error: %w", waitErr)
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

// InitChild executes inside the new namespace before the target workload runs.
// It sets up the mount namespace, mounts a tmpfs root, binds read-only system dirs,
// drops privileges, and executes the user program via syscall.Exec.
func InitChild(cfgJSON string) error {
	var cfg Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return fmt.Errorf("child: failed to parse config: %w", err)
	}

	// 1. Prevent mount events from propagating back to host
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("child: failed to make root private: %w", err)
	}

	// 2. Create a temporary directory in memory for our new jail root
	targetRoot, err := os.MkdirTemp("", "gojail-root-*")
	if err != nil {
		return fmt.Errorf("child: failed to create jail root tempdir: %w", err)
	}
	defer os.RemoveAll(targetRoot)

	// Mount a pristine tmpfs at our new root
	if err := syscall.Mount("tmpfs", targetRoot, "tmpfs", 0, "size=64m"); err != nil {
		return fmt.Errorf("child: failed to mount tmpfs root: %w", err)
	}

	// 3. Bind mount essential system directories as strictly Read-Only
	essentialDirs := []string{"bin", "lib", "lib64", "usr", "etc"}
	for _, dir := range essentialDirs {
		src := "/" + dir
		if fi, err := os.Stat(src); err == nil && fi.IsDir() {
			dst := filepath.Join(targetRoot, dir)
			if err := os.MkdirAll(dst, 0755); err != nil {
				return fmt.Errorf("child: failed to mkdir %s: %w", dst, err)
			}
			// Bind mount from host
			if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
				return fmt.Errorf("child: failed to bind mount %s: %w", dir, err)
			}
			// Remount as Read-Only
			if err := syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
				return fmt.Errorf("child: failed to remount %s read-only: %w", dir, err)
			}
		}
	}

	// 4. Create an isolated writable /tmp inside the sandbox
	sandboxTmp := filepath.Join(targetRoot, "tmp")
	if err := os.MkdirAll(sandboxTmp, 1777); err != nil {
		return fmt.Errorf("child: failed to create sandbox /tmp: %w", err)
	}
	if err := syscall.Mount("tmpfs", sandboxTmp, "tmpfs", 0, "size=32m"); err != nil {
		return fmt.Errorf("child: failed to mount sandbox /tmp tmpfs: %w", err)
	}

	// 5. Chroot into the new isolated root filesystem
	if err := syscall.Chroot(targetRoot); err != nil {
		return fmt.Errorf("child: chroot failed: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("child: chdir to / failed: %w", err)
	}

	// 6. Drop privileges to nobody (65534)
	const unprivilegedUID = 65534
	const unprivilegedGID = 65534
	if err := syscall.Setgid(unprivilegedGID); err != nil {
		return fmt.Errorf("child: setgid failed: %w", err)
	}
	if err := syscall.Setuid(unprivilegedUID); err != nil {
		return fmt.Errorf("child: setuid failed: %w", err)
	}

	// 7. Execute the user payload, replacing the init process
	binaryPath, err := exec.LookPath(cfg.Command)
	if err != nil {
		return fmt.Errorf("child: command not found: %w", err)
	}

	execArgs := append([]string{cfg.Command}, cfg.Args...)
	if err := syscall.Exec(binaryPath, execArgs, cfg.Env); err != nil {
		return fmt.Errorf("child: exec failed: %w", err)
	}

	return nil
}