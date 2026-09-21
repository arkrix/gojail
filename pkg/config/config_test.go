package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_DefaultValues(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.SocketPath != "/var/run/gojail.sock" {
		t.Errorf("unexpected default socket path: %s", cfg.Server.SocketPath)
	}
	if cfg.Pool.WarmWorkers != 2 {
		t.Errorf("unexpected default worker count: %d", cfg.Pool.WarmWorkers)
	}
	if cfg.Defaults.MemoryLimitMB != 128 {
		t.Errorf("unexpected default memory limit: %d", cfg.Defaults.MemoryLimitMB)
	}
}

func TestConfig_LoadCustomYAML(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "test-config.yaml")

	yamlContent := `
server:
  socket_path: "/tmp/custom-gojail.sock"
  socket_mode: 0660
pool:
  warm_workers: 5
defaults:
  memory_limit_mb: 256
  max_processes: 128
  timeout_sec: 15
`
	if err := os.WriteFile(confPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(confPath)
	if err != nil {
		t.Fatalf("failed to load custom config: %v", err)
	}

	if cfg.Server.SocketPath != "/tmp/custom-gojail.sock" {
		t.Errorf("expected custom socket path, got: %s", cfg.Server.SocketPath)
	}
	if cfg.Pool.WarmWorkers != 5 {
		t.Errorf("expected 5 warm workers, got: %d", cfg.Pool.WarmWorkers)
	}
	if cfg.Defaults.MemoryLimitMB != 256 {
		t.Errorf("expected 256MB memory limit, got: %d", cfg.Defaults.MemoryLimitMB)
	}
}
