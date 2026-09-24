package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDNSList_Custom(t *testing.T) {
	custom := []string{"9.9.9.9", "1.1.1.1", "invalid-ip"}
	res := ResolveDNSList(custom)
	if len(res) != 2 {
		t.Fatalf("expected 2 valid IPs, got %v", res)
	}
	if res[0] != "9.9.9.9" || res[1] != "1.1.1.1" {
		t.Errorf("unexpected DNS list: %v", res)
	}
}

func TestParseHostResolvConf_FiltersLoopback(t *testing.T) {
	content := `
# Systemd resolver
nameserver 127.0.0.53
nameserver 192.168.1.1
# Secondary
nameserver 8.8.4.4
`
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "resolv.conf")
	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write dummy resolv.conf: %v", err)
	}

	servers := parseHostResolvConf(confPath)
	if len(servers) != 2 {
		t.Fatalf("expected 2 non-loopback servers, got %d: %v", len(servers), servers)
	}
	if servers[0] != "192.168.1.1" || servers[1] != "8.8.4.4" {
		t.Errorf("unexpected parsed servers: %v", servers)
	}
}

func TestInjectResolvConf(t *testing.T) {
	tmpRoot := t.TempDir()
	dns := []string{"1.0.0.1"}

	if err := InjectResolvConf(tmpRoot, dns); err != nil {
		t.Fatalf("InjectResolvConf failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpRoot, "etc", "resolv.conf"))
	if err != nil {
		t.Fatalf("failed to read injected resolv.conf: %v", err)
	}

	if !strings.Contains(string(data), "nameserver 1.0.0.1") {
		t.Errorf("expected resolv.conf to contain nameserver 1.0.0.1, got:\n%s", string(data))
	}
}
