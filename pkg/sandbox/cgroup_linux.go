package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultCgroupRoot = "/sys/fs/cgroup/gojail"

// LiveStats contains instantaneous resource readings from cgroups v2.
type LiveStats struct {
	MemoryCurrentBytes int64
	MemoryPeakBytes    int64
	CPUUsageUS         int64
	PIDsCurrent        int64
}

// CgroupController manages resource limits and monitoring via Cgroups v2.
type CgroupController struct {
	id         string
	cgroupPath string
	prevCPUUS  int64
	prevTime   time.Time
}

// NewCgroupController initializes a new cgroup v2 group for a sandbox.
func NewCgroupController(id string) (*CgroupController, error) {
	cgroupPath := filepath.Join(defaultCgroupRoot, id)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cgroup directory %s: %w", cgroupPath, err)
	}

	return &CgroupController{
		id:         id,
		cgroupPath: cgroupPath,
		prevTime:   time.Now(),
	}, nil
}

// ApplyLimits configures memory and process limits.
func (c *CgroupController) ApplyLimits(memLimitBytes int64, maxProcs int64) error {
	if memLimitBytes > 0 {
		memFile := filepath.Join(c.cgroupPath, "memory.max")
		if err := os.WriteFile(memFile, []byte(strconv.FormatInt(memLimitBytes, 10)), 0644); err != nil {
			return fmt.Errorf("failed to set memory.max: %w", err)
		}
	}

	if maxProcs > 0 {
		pidsFile := filepath.Join(c.cgroupPath, "pids.max")
		if err := os.WriteFile(pidsFile, []byte(strconv.FormatInt(maxProcs, 10)), 0644); err != nil {
			return fmt.Errorf("failed to set pids.max: %w", err)
		}
	}

	return nil
}

// AttachPID associates a running host PID with this cgroup slice.
func (c *CgroupController) AttachPID(pid int) error {
	procsFile := filepath.Join(c.cgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to attach pid %d to cgroup: %w", pid, err)
	}
	return nil
}

// Freeze halts execution of all processes inside this cgroup.
func (c *CgroupController) Freeze() error {
	freezeFile := filepath.Join(c.cgroupPath, "cgroup.freeze")
	return os.WriteFile(freezeFile, []byte("1"), 0644)
}

// Thaw resumes execution of frozen processes.
func (c *CgroupController) Thaw() error {
	freezeFile := filepath.Join(c.cgroupPath, "cgroup.freeze")
	return os.WriteFile(freezeFile, []byte("0"), 0644)
}

// SampleStats samples current memory usage, peak memory, CPU time, and active pids.
func (c *CgroupController) SampleStats() (LiveStats, float64, error) {
	var stats LiveStats

	// 1. Current Memory
	if data, err := os.ReadFile(filepath.Join(c.cgroupPath, "memory.current")); err == nil {
		stats.MemoryCurrentBytes, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}

	// 2. Peak Memory
	if data, err := os.ReadFile(filepath.Join(c.cgroupPath, "memory.peak")); err == nil {
		stats.MemoryPeakBytes, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}

	// 3. Current PIDs
	if data, err := os.ReadFile(filepath.Join(c.cgroupPath, "pids.current")); err == nil {
		stats.PIDsCurrent, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}

	// 4. CPU Usage
	var userUS, sysUS int64
	if file, err := os.Open(filepath.Join(c.cgroupPath, "cpu.stat")); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 {
				if fields[0] == "user_usec" {
					userUS, _ = strconv.ParseInt(fields[1], 10, 64)
				} else if fields[0] == "system_usec" {
					sysUS, _ = strconv.ParseInt(fields[1], 10, 64)
				}
			}
		}
		_ = file.Close()
	}

	totalCPUUS := userUS + sysUS
	stats.CPUUsageUS = totalCPUUS

	now := time.Now()
	elapsedUS := now.Sub(c.prevTime).Microseconds()

	var cpuPercent float64
	if elapsedUS > 0 && c.prevCPUUS > 0 && totalCPUUS >= c.prevCPUUS {
		deltaCPUUS := totalCPUUS - c.prevCPUUS
		cpuPercent = (float64(deltaCPUUS) / float64(elapsedUS)) * 100.0
	}

	c.prevCPUUS = totalCPUUS
	c.prevTime = now

	return stats, cpuPercent, nil
}

// ReadMetrics parses final post-execution metrics from cgroup controllers.
func (c *CgroupController) ReadMetrics() ResourceMetrics {
	var metrics ResourceMetrics

	// Peak memory
	if data, err := os.ReadFile(filepath.Join(c.cgroupPath, "memory.peak")); err == nil {
		metrics.PeakMemoryBytes, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	} else if data, err := os.ReadFile(filepath.Join(c.cgroupPath, "memory.current")); err == nil {
		metrics.PeakMemoryBytes, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}

	// CPU times
	if file, err := os.Open(filepath.Join(c.cgroupPath, "cpu.stat")); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 {
				if fields[0] == "user_usec" {
					metrics.UserCPUTimeUS, _ = strconv.ParseInt(fields[1], 10, 64)
				} else if fields[0] == "system_usec" {
					metrics.SystemCPUTimeUS, _ = strconv.ParseInt(fields[1], 10, 64)
				}
			}
		}
		_ = file.Close()
	}

	return metrics
}

// Cleanup removes the cgroup slice directory after container termination.
func (c *CgroupController) Cleanup() error {
	procsFile := filepath.Join(c.cgroupPath, "cgroup.procs")
	if data, err := os.ReadFile(procsFile); err == nil {
		pids := strings.Fields(string(data))
		for _, pidStr := range pids {
			if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
	_ = os.Remove(c.cgroupPath)
	return nil
}
