package sandbox

import (
	"os/exec"
	"testing"
)

func TestWorkerAccessors(t *testing.T) {
	cmd := exec.Command("/bin/echo")
	w := &Worker{
		ID:        "test-worker-1",
		rootPath:  "/tmp/test-rootfs",
		cmd:       cmd,
		StorageMB: 64,
	}

	if w.RootPath() != "/tmp/test-rootfs" {
		t.Errorf("expected rootPath /tmp/test-rootfs, got %s", w.RootPath())
	}

	// Before start, PID should be 0
	if w.PID() != 0 {
		t.Errorf("expected PID 0 before process start, got %d", w.PID())
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start echo cmd: %v", err)
	}
	defer func() {
		_ = cmd.Wait()
	}()

	if w.PID() != cmd.Process.Pid {
		t.Errorf("expected PID %d, got %d", cmd.Process.Pid, w.PID())
	}
}
