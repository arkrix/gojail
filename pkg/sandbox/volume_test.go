package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMountSpec(t *testing.T) {
	tmpDir := t.TempDir()

	spec, err := ParseMountSpec(tmpDir + ":/data:ro")
	if err != nil {
		t.Fatalf("ParseMountSpec failed: %v", err)
	}
	if !spec.ReadOnly {
		t.Errorf("expected ReadOnly=true, got %v", spec.ReadOnly)
	}
	if spec.ContainerPath != "/data" {
		t.Errorf("expected /data, got %s", spec.ContainerPath)
	}

	specRW, err := ParseMountSpec(tmpDir + ":/workspace")
	if err != nil {
		t.Fatalf("ParseMountSpec failed: %v", err)
	}
	if specRW.ReadOnly {
		t.Errorf("expected default ReadOnly=false, got true")
	}
}

func TestIntegration_VolumeMountReadOnly(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping test; root privileges required")
	}

	tmpHostDir := t.TempDir()
	_ = os.Chmod(tmpHostDir, 0777)

	canaryFile := filepath.Join(tmpHostDir, "source.txt")
	// 0666 ensures DAC permissions pass for unprivileged UID 65534 (nobody),
	// forcing the kernel to evaluate the VFS mount read-only flag (EROFS).
	if err := os.WriteFile(canaryFile, []byte("readonly_content\n"), 0666); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := Config{
		ID:             "test-vol-ro",
		Timeout:        3 * time.Second,
		Command:        "/bin/sh",
		Args:           []string{"-c", "cat /mnt/host/source.txt && echo 'bad' >> /mnt/host/source.txt"},
		StorageLimitMB: 16,
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		Mounts: []MountSpec{
			{
				HostPath:      tmpHostDir,
				ContainerPath: "/mnt/host",
				ReadOnly:      true,
			},
		},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run failed: %v", err)
	}

	if !strings.Contains(res.Stdout, "readonly_content") {
		t.Errorf("expected to read source file from mount, got: %s", res.Stdout)
	}

	// Writing to read-only mount must fail either via EROFS or EACCES
	combined := res.Stdout + res.Stderr
	if !strings.Contains(combined, "Read-only file system") && !strings.Contains(combined, "Permission denied") {
		t.Errorf("expected 'Read-only file system' or 'Permission denied' on write attempt, got: %s", combined)
	}
}

func TestIntegration_VolumeMountReadWrite(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping test; root privileges required")
	}

	tmpHostDir := t.TempDir()
	// Set permissions so unprivileged UID 65534 (nobody) can write into tmpHostDir
	_ = os.Chmod(tmpHostDir, 0777)

	cfg := Config{
		ID:             "test-vol-rw",
		Timeout:        3 * time.Second,
		Command:        "/bin/sh",
		Args:           []string{"-c", "echo 'persisted' > /mnt/data/result.txt"},
		StorageLimitMB: 16,
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		Mounts: []MountSpec{
			{
				HostPath:      tmpHostDir,
				ContainerPath: "/mnt/data",
				ReadOnly:      false,
			},
		},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", res.ExitCode, res.Stderr)
	}

	// Verify the file exists on the host
	outPath := filepath.Join(tmpHostDir, "result.txt")
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected file %s to exist on host: %v", outPath, err)
	}

	if strings.TrimSpace(string(content)) != "persisted" {
		t.Errorf("expected 'persisted', got: %s", string(content))
	}
}
