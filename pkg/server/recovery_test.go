package server

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAcquireDaemonLock_Exclusive(t *testing.T) {
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	f1, err := AcquireDaemonLock(pidPath)
	if err != nil {
		t.Fatalf("first AcquireDaemonLock failed: %v", err)
	}
	defer func() {
		_ = syscall.Flock(int(f1.Fd()), syscall.LOCK_UN)
		_ = f1.Close()
	}()

	// Second acquisition must fail
	f2, err := AcquireDaemonLock(pidPath)
	if err == nil {
		_ = syscall.Flock(int(f2.Fd()), syscall.LOCK_UN)
		_ = f2.Close()
		t.Fatal("expected second lock acquisition to fail, but succeeded")
	}
}

func TestSweepStaleMounts_DetachesOrphanMount(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping mount sweep test; root privileges required")
	}

	testLayersDir := filepath.Join("/run/gojail/layers", "test-sweep")
	mountPoint := filepath.Join(testLayersDir, "mounted")

	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("failed to mkdir mountPoint: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(testLayersDir)
	}()

	// Mount a tmpfs inside the target path
	if err := syscall.Mount("tmpfs", mountPoint, "tmpfs", 0, "size=4m"); err != nil {
		t.Fatalf("failed to setup test tmpfs mount: %v", err)
	}

	// Run mount sweep
	unmounted, err := SweepStaleMounts(testLayersDir)
	if err != nil {
		t.Fatalf("SweepStaleMounts failed: %v", err)
	}

	if unmounted < 1 {
		t.Errorf("expected at least 1 mount to be detached, got %d", unmounted)
	}
}
