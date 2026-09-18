package sandbox

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const cgroupRoot = "/sys/fs/cgroup"
const gojailSubtree = "/sys/fs/cgroup/gojail"

// CgroupController manages cgroups v2 resource limits and state for a sandbox.
type CgroupController struct {
	id   string
	path string
}

// NewCgroupController creates a dedicated cgroup directory for a sandbox.
func NewCgroupController(id string) (*CgroupController, error) {
	if err := os.MkdirAll(gojailSubtree, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base gojail cgroup: %w", err)
	}

	subtreeControl := filepath.Join(gojailSubtree, "cgroup.subtree_control")
	if err := os.WriteFile(subtreeControl, []byte("+memory +pids +cpu"), 0644); err != nil {
		_ = err
	}

	jailPath := filepath.Join(gojailSubtree, id)
	if err := os.Mkdir(jailPath, 0755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("failed to create sandbox cgroup %s: %w", id, err)
	}

	return &CgroupController{
		id:   id,
		path: jailPath,
	}, nil
}

// ApplyLimits writes memory and process ceilings to the cgroup.
func (c *CgroupController) ApplyLimits(memoryLimitBytes, maxProcesses int64) error {
	if memoryLimitBytes > 0 {
		memFile := filepath.Join(c.path, "memory.max")
		if err := os.WriteFile(memFile, []byte(strconv.FormatInt(memoryLimitBytes, 10)), 0644); err != nil {
			return fmt.Errorf("failed to write memory.max: %w", err)
		}
	}

	if maxProcesses > 0 {
		pidsFile := filepath.Join(c.path, "pids.max")
		if err := os.WriteFile(pidsFile, []byte(strconv.FormatInt(maxProcesses, 10)), 0644); err != nil {
			return fmt.Errorf("failed to write pids.max: %w", err)
		}
	}

	return nil
}

// AttachPID assigns a process ID to this cgroup slice.
func (c *CgroupController) AttachPID(pid int) error {
	procsFile := filepath.Join(c.path, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to attach pid %d to %s: %w", pid, procsFile, err)
	}
	return nil
}

// Freeze writes 1 to cgroup.freeze and waits until cgroup.events confirms frozen=1.
func (c *CgroupController) Freeze() error {
	freezeFile := filepath.Join(c.path, "cgroup.freeze")
	if err := os.WriteFile(freezeFile, []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to write cgroup.freeze: %w", err)
	}

	eventsFile := filepath.Join(c.path, "cgroup.events")
	deadline := time.Now().Add(500 * time.Millisecond)

	for time.Now().Before(deadline) {
		data, err := os.ReadFile(eventsFile)
		if err == nil && bytes.Contains(data, []byte("frozen 1")) {
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}

	return nil
}

// Thaw writes 0 to cgroup.freeze to wake all processes in the cgroup.
func (c *CgroupController) Thaw() error {
	freezeFile := filepath.Join(c.path, "cgroup.freeze")
	if err := os.WriteFile(freezeFile, []byte("0"), 0644); err != nil {
		return fmt.Errorf("failed to thaw cgroup: %w", err)
	}
	return nil
}

// ReadMetrics parses resource usage statistics from the cgroup files.
func (c *CgroupController) ReadMetrics() ResourceMetrics {
	var metrics ResourceMetrics

	// 1. Read peak memory usage; fallback to memory.current if memory.peak is absent
	memData, err := os.ReadFile(filepath.Join(c.path, "memory.peak"))
	if err != nil {
		memData, _ = os.ReadFile(filepath.Join(c.path, "memory.current"))
	}
	if len(memData) > 0 {
		val, parseErr := strconv.ParseInt(strings.TrimSpace(string(memData)), 10, 64)
		if parseErr == nil {
			metrics.PeakMemoryBytes = val
		}
	}

	// 2. Read CPU stats from cpu.stat
	cpuFile, err := os.Open(filepath.Join(c.path, "cpu.stat"))
	if err == nil {
		defer cpuFile.Close()
		scanner := bufio.NewScanner(cpuFile)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 {
				switch fields[0] {
				case "user_usec":
					metrics.UserCPUTimeUS, _ = strconv.ParseInt(fields[1], 10, 64)
				case "system_usec":
					metrics.SystemCPUTimeUS, _ = strconv.ParseInt(fields[1], 10, 64)
				}
			}
		}
	}

	return metrics
}

// Cleanup removes the ephemeral leaf cgroup, thawing first if frozen.
func (c *CgroupController) Cleanup() error {
	_ = c.Thaw()
	if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cgroup %s: %w", c.path, err)
	}
	return nil
}
