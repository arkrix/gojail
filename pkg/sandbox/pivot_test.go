package sandbox

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegration_PivotRootIsolation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping test; root privileges required for pivot_root")
	}

	cfg := Config{
		ID:             "test-pivot-root",
		Timeout:        3 * time.Second,
		Command:        "/bin/sh",
		Args:           []string{"-c", "ls -d /.oldroot 2>&1 || echo 'oldroot_gone'"},
		StorageLimitMB: 16,
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	combined := res.Stdout + res.Stderr
	if !strings.Contains(combined, "No such file or directory") && !strings.Contains(combined, "oldroot_gone") {
		t.Errorf("expected .oldroot to be unmounted and removed, got output: %s", combined)
	}
}
