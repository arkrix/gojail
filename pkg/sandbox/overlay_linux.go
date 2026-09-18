package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// OverlayManager manages ephemeral union filesystem layers for a sandbox.
type OverlayManager struct {
	id         string
	baseDir    string
	upperDir   string
	workDir    string
	mergedDir  string
	storageMB  int64
}

// NewOverlayManager prepares layer directories under /run/gojail/layers/<id>.
func NewOverlayManager(id string, storageLimitMB int64) (*OverlayManager, error) {
	if storageLimitMB <= 0 {
		storageLimitMB = 64 // 64 MB default writable layer
	}

	baseDir := filepath.Join("/run/gojail/layers", id)
	upperDir := filepath.Join(baseDir, "upper")
	workDir := filepath.Join(baseDir, "work")
	mergedDir := filepath.Join(baseDir, "merged")

	// Ensure base directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create overlay root %s: %w", baseDir, err)
	}

	// Mount a dedicated tmpfs onto baseDir to strictly enforce storage quotas
	tmpfsOpts := fmt.Sprintf("size=%dm", storageLimitMB)
	if err := syscall.Mount("tmpfs", baseDir, "tmpfs", 0, tmpfsOpts); err != nil {
		_ = os.RemoveAll(baseDir)
		return nil, fmt.Errorf("failed to mount tmpfs for overlay storage limit: %w", err)
	}

	// Create subdirectories inside the tmpfs-backed layer
	for _, dir := range []string{upperDir, workDir, mergedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			_ = syscall.Unmount(baseDir, syscall.MNT_DETACH)
			_ = os.RemoveAll(baseDir)
			return nil, fmt.Errorf("failed to create overlay directory %s: %w", dir, err)
		}
	}

	return &OverlayManager{
		id:         id,
		baseDir:    baseDir,
		upperDir:   upperDir,
		workDir:    workDir,
		mergedDir:  mergedDir,
		storageMB:  storageLimitMB,
	}, nil
}

// Mount merges the host root (read-only lowerdir) with the ephemeral upperdir.
func (om *OverlayManager) Mount() (string, error) {
	// lowerdir=/ (host root), upperdir=upper, workdir=work
	// The kernel requires upperdir and workdir to be on the same filesystem (which our tmpfs guarantees).
	opts := fmt.Sprintf("lowerdir=/,upperdir=%s,workdir=%s", om.upperDir, om.workDir)

	if err := syscall.Mount("overlay", om.mergedDir, "overlay", 0, opts); err != nil {
		return "", fmt.Errorf("failed to mount overlayfs: %w", err)
	}

	return om.mergedDir, nil
}

// MergedDir returns the root mount point to chroot into.
func (om *OverlayManager) MergedDir() string {
	return om.mergedDir
}

// Cleanup unmounts the overlay union, unmounts the tmpfs quota, and removes directories.
func (om *OverlayManager) Cleanup() error {
	var errs []error

	// 1. Unmount the merged overlay layer
	if err := syscall.Unmount(om.mergedDir, syscall.MNT_DETACH); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("failed to unmount overlay merged dir: %w", err))
	}

	// 2. Unmount the underlying tmpfs quota backing baseDir
	if err := syscall.Unmount(om.baseDir, syscall.MNT_DETACH); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("failed to unmount overlay tmpfs base: %w", err))
	}

	// 3. Delete leftover layer directories
	if err := os.RemoveAll(om.baseDir); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("failed to remove layer base %s: %w", om.baseDir, err))
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
