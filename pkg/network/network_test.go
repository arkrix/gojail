package network

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("expected non-nil Manager")
	}
	if m.bridgeName != DefaultBridgeName {
		t.Errorf("expected bridgeName %s, got %s", DefaultBridgeName, m.bridgeName)
	}
	if m.IPAM() == nil {
		t.Fatal("expected initialized IPAM in Manager")
	}
}

func TestEnsureBridge(t *testing.T) {
	m := NewManager()
	_, err := m.EnsureBridge()
	if err != nil {
		t.Skipf("skipping bridge test; requires root permissions: %v", err)
	}
}
