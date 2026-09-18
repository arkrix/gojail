package sandbox

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegration_OverlayFilesystemIsolation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping test; root privileges required for overlayfs")
	}

	// Try writing a file to /etc/gojail_canary.txt inside the sandbox
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
