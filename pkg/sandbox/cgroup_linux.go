package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const cgroupRoot = "/sys/fs/cgroup"
const gojailSubtree = "/sys/fs/cgroup/gojail"

// CgroupController manages cgroups v2 resource limits for a sandboxed execution.
type CgroupController struct {
	id   string
	path string
}

// NewCgroupController creates a dedicated cgroup directory for a sandbox.
func NewCgroupController(id string) (*CgroupController, error) {
	// 1. Ensure the parent delegation subtree exists
	if err := os.MkdirAll(gojailSubtree, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base gojail cgroup: %w", err)
	}

	// 2. Delegate memory and pids controllers down the subtree
	subtreeControl := filepath.Join(gojailSubtree, "cgroup.subtree_control")
	if err := os.WriteFile(subtreeControl, []byte("+memory +pids"), 0644); err != nil {
		// Non-fatal if controllers are already enabled
		_ = err
	}

	// 3. Create unique isolated leaf cgroup for this execution
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

// Cleanup removes the ephemeral leaf cgroup.
func (c *CgroupController) Cleanup() error {
	if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cgroup %s: %w", c.path, err)
	}
	return nil
}
