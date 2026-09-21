package seccomp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProfile_Default(t *testing.T) {
	prof, err := LoadProfile("")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if prof.DefaultAction != ActionAllow {
		t.Fatalf("expected default action allow, got %v", prof.DefaultAction)
	}
	if len(prof.Syscalls) == 0 {
		t.Fatalf("expected hardened default rules, got empty slice")
	}
}

func TestLoadProfile_CustomJSON(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "profile.json")

	content := `{
		"default_action": "errno",
		"syscalls": [
			{"name": "write", "action": "allow"},
			{"name": "read", "action": "allow"}
		]
	}`

	if err := os.WriteFile(jsonPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test profile: %v", err)
	}

	prof, err := LoadProfile(jsonPath)
	if err != nil {
		t.Fatalf("failed to load custom profile: %v", err)
	}

	if prof.DefaultAction != ActionErrno {
		t.Errorf("expected default action errno, got %s", prof.DefaultAction)
	}
	if len(prof.Syscalls) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(prof.Syscalls))
	}
}

func TestCompileBPF(t *testing.T) {
	prof := DefaultHardenedProfile()
	filter, err := compileBPF(prof)
	if err != nil {
		t.Fatalf("compileBPF failed: %v", err)
	}

	if len(filter) < 5 {
		t.Fatalf("expected compiled BPF filter instructions, got length %d", len(filter))
	}

	if filter[0].k != 4 {
		t.Errorf("expected first instruction to load arch from offset 4, got %d", filter[0].k)
	}
}
