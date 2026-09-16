package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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

	cfgBytes, err := json.Marshal(r.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}

	selfBin, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.CommandContext(ctx, selfBin, "__init_child__", string(cfgBytes))

	// Allocate new namespaces: Mount, PID, UTS, IPC, Network
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

// configureLoopback activates 'lo' interface inside the new network namespace
func configureLoopback() error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("failed to find lo interface: %w", err)
	}

	// Equivalent to: ip link set lo up
	if err := unix.IoctlSetInt(0, unix.SIOCSIFFLAGS, lo.Index); err != nil {
		// Ignore if non-fatal or use netlink fallback
		_ = err
	}
	return nil
}

// InitChild executes inside the new namespace before the target workload runs.
func InitChild(cfgJSON string) error {
	var cfg Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return fmt.Errorf("child: failed to parse config: %w", err)
	}

	// 1. Private mount propagation
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("child: failed to make root private: %w", err)
	}

	// 2. Ephemeral tmpfs jail root
	targetRoot, err := os.MkdirTemp("", "gojail-root-*")
	if err != nil {
		return fmt.Errorf("child: failed to create jail root tempdir: %w", err)
	}
	defer os.RemoveAll(targetRoot)

	if err := syscall.Mount("tmpfs", targetRoot, "tmpfs", 0, "size=64m"); err != nil {
		return fmt.Errorf("child: failed to mount tmpfs root: %w", err)
	}

	// 3. Bind mount system binaries & libraries as Read-Only
	essentialDirs := []string{"bin", "lib", "lib64", "usr", "etc"}
	for _, dir := range essentialDirs {
		src := "/" + dir
		if fi, err := os.Stat(src); err == nil && fi.IsDir() {
			dst := filepath.Join(targetRoot, dir)
			if err := os.MkdirAll(dst, 0755); err != nil {
				return fmt.Errorf("child: failed to mkdir %s: %w", dst, err)
			}
			if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
				return fmt.Errorf("child: failed to bind mount %s: %w", dir, err)
			}
			if err := syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
				return fmt.Errorf("child: failed to remount %s read-only: %w", dir, err)
			}
		}
	}

	// 4. Isolated writable /tmp
	sandboxTmp := filepath.Join(targetRoot, "tmp")
	if err := os.MkdirAll(sandboxTmp, 1777); err != nil {
		return fmt.Errorf("child: failed to create sandbox /tmp: %w", err)
	}
	if err := syscall.Mount("tmpfs", sandboxTmp, "tmpfs", 0, "size=32m"); err != nil {
		return fmt.Errorf("child: failed to mount sandbox /tmp: %w", err)
	}

	// 5. Chroot into the jail root
	if err := syscall.Chroot(targetRoot); err != nil {
		return fmt.Errorf("child: chroot failed: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("child: chdir to / failed: %w", err)
	}

	// 6. Network initialization (keep lo alive, but egress disabled)
	_ = configureLoopback()

	// 7. Drop capabilities and enable PR_SET_NO_NEW_PRIVS
	if err := DropCapabilities(); err != nil {
		return fmt.Errorf("child: capability drop failed: %w", err)
	}

	// 8. Apply Seccomp BPF syscall filter
	if err := ApplySeccompDenylist(); err != nil {
		return fmt.Errorf("child: seccomp filter failed: %w", err)
	}

	// 9. Drop user credentials down to nobody (65534)
	const unprivilegedUID = 65534
	const unprivilegedGID = 65534
	if err := syscall.Setgid(unprivilegedGID); err != nil {
		return fmt.Errorf("child: setgid failed: %w", err)
	}
	if err := syscall.Setuid(unprivilegedUID); err != nil {
		return fmt.Errorf("child: setuid failed: %w", err)
	}

	// 10. Execute the requested binary
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
