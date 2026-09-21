package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegration_OverlayFilesystemIsolation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping test; root privileges required for overlayfs")
	}

	cfg := Config{
		ID:             "test-overlay-canary",
		Timeout:        3 * time.Second,
		Command:        "/bin/sh",
		Args:           []string{"-c", "echo 'isolated' > /tmp/canary.txt && cat /tmp/canary.txt"},
		StorageLimitMB: 16,
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run() failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", res.ExitCode, res.Stderr)
	}

	if !strings.Contains(res.Stdout, "isolated") {
		t.Errorf("expected 'isolated' in stdout, got: %s", res.Stdout)
	}

	// Verify that the file did NOT leak to the host filesystem
	if _, err := os.Stat("/tmp/canary.txt"); !os.IsNotExist(err) {
		_ = os.Remove("/tmp/canary.txt")
		t.Fatal("file leaked from overlay jail to host filesystem!")
	}
}

func TestIntegration_StorageQuotaExceeded(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping test; root privileges required for overlayfs")
	}

	testID := "test-quota-exceeded"
	layerPath := filepath.Join("/run/gojail/layers", testID)

	// Configure strict 8 MB upper limit and attempt to write 16 MB
	cfg := Config{
		ID:             testID,
		Timeout:        5 * time.Second,
		Command:        "/bin/sh",
		Args:           []string{"-c", "dd if=/dev/zero of=/tmp/overflow.dat bs=1M count=16 2>&1"},
		StorageLimitMB: 8,
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run() failed unexpectedly: %v", err)
	}

	// dd must report out of space
	combinedOutput := res.Stdout + res.Stderr
	if !strings.Contains(combinedOutput, "No space left on device") {
		t.Errorf("expected 'No space left on device' in output, got: %s", combinedOutput)
	}

	// Verify complete layer teardown and zero leaking mount points
	if _, err := os.Stat(layerPath); !os.IsNotExist(err) {
		t.Errorf("layer directory %s was not cleaned up after quota failure", layerPath)
	}

	// Verify mount table does not retain leaked mounts for this container ID
	mountsData, err := os.ReadFile("/proc/mounts")
	if err == nil {
		if strings.Contains(string(mountsData), layerPath) {
			t.Errorf("leaked mount detected in /proc/mounts for %s", layerPath)
		}
	}
}
