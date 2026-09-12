package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const cgroupV2Root = "/sys/fs/cgroup/gojail"

// CgroupController handles creation and resource constraints via cgroups v2.
type CgroupController struct {
	path string
}

// ensureSubtreeControl ensures the specified controllers are enabled in subtree_control.
func ensureSubtreeControl(path string, controllers []string) error {
	controlFile := filepath.Join(path, "cgroup.subtree_control")
	content, err := os.ReadFile(controlFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", controlFile, err)
	}

	enabled := string(content)
	var toEnable []string
	for _, ctrl := range controllers {
		if !strings.Contains(enabled, ctrl) {
			toEnable = append(toEnable, "+"+ctrl)
		}
	}

	if len(toEnable) > 0 {
		payload := strings.Join(toEnable, " ")
		if err := os.WriteFile(controlFile, []byte(payload), 0644); err != nil {
			return fmt.Errorf("failed to write %q to %s: %w", payload, controlFile, err)
		}
	}

	return nil
}

// initBaseCgroup ensures the root gojail directory exists and has controllers enabled.
func initBaseCgroup() error {
	// First ensure the top-level cgroup delegates memory and pids
	_ = ensureSubtreeControl("/sys/fs/cgroup", []string{"memory", "pids"})

	if err := os.MkdirAll(cgroupV2Root, 0755); err != nil {
		return fmt.Errorf("failed to create base cgroup dir %s: %w", cgroupV2Root, err)
	}

	// Ensure the gojail base cgroup propagates controllers to sandbox subtrees
	if err := ensureSubtreeControl(cgroupV2Root, []string{"memory", "pids"}); err != nil {
		return fmt.Errorf("failed to enable subtree controllers on %s: %w", cgroupV2Root, err)
	}

	return nil
}

// NewCgroupController creates a dedicated cgroup v2 subtree for the sandbox ID.
func NewCgroupController(sandboxID string) (*CgroupController, error) {
	if err := initBaseCgroup(); err != nil {
		return nil, err
	}

	cgPath := filepath.Join(cgroupV2Root, sandboxID)
	if err := os.MkdirAll(cgPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cgroup directory at %s: %w", cgPath, err)
	}

	return &CgroupController{path: cgPath}, nil
}

// ApplyLimits writes CPU, memory, and process ceiling configurations.
func (c *CgroupController) ApplyLimits(memBytes int64, maxPids int64) error {
	if memBytes > 0 {
		memFile := filepath.Join(c.path, "memory.max")
		if err := os.WriteFile(memFile, []byte(strconv.FormatInt(memBytes, 10)), 0644); err != nil {
			return fmt.Errorf("failed to set memory.max: %w", err)
		}
	}

	if maxPids > 0 {
		pidsFile := filepath.Join(c.path, "pids.max")
		if err := os.WriteFile(pidsFile, []byte(strconv.FormatInt(maxPids, 10)), 0644); err != nil {
			return fmt.Errorf("failed to set pids.max: %w", err)
		}
	}

	return nil
}

// AttachPID binds the target process to this isolated cgroup slice.
func (c *CgroupController) AttachPID(pid int) error {
	procsFile := filepath.Join(c.path, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to attach pid %d to cgroup: %w", pid, err)
	}
	return nil
}

// Cleanup removes the cgroup slice once the process exits.
func (c *CgroupController) Cleanup() error {
	if err := os.Remove(c.path); err != nil {
		return fmt.Errorf("failed to remove cgroup path %s: %w", c.path, err)
	}
	return nil
}