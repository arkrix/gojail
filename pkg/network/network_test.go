package network

import (
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestEnsureBridge(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping bridge test; requires root permissions")
	}

	mgr := NewManager()
	br, err := mgr.EnsureBridge()
	if err != nil {
		t.Fatalf("EnsureBridge failed: %v", err)
	}

	link, err := netlink.LinkByName(mgr.bridgeName)
	if err != nil {
		t.Fatalf("failed to find created bridge: %v", err)
	}

	if link.Attrs().Name != mgr.bridgeName {
		t.Errorf("expected bridge name %s, got %s", mgr.bridgeName, link.Attrs().Name)
	}

	// Verify IP address on bridge
	addrs, err := netlink.AddrList(br, netlink.FAMILY_V4)
	if err != nil || len(addrs) == 0 {
		t.Fatalf("expected IPv4 address on bridge, found none")
	}

	if addrs[0].IP.String() != "10.200.0.1" {
		t.Errorf("expected bridge IP 10.200.0.1, got %s", addrs[0].IP.String())
	}
}
