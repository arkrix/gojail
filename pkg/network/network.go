package network

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	DefaultBridgeName = "gojail0"
	DefaultBridgeCIDR = "10.200.0.1/24"
	DefaultSubnetIP   = "10.200.0."
)

// Manager coordinates host bridge devices and container veth pairings.
type Manager struct {
	bridgeName string
	bridgeCIDR string
}

// NewManager initializes a network manager instance.
func NewManager() *Manager {
	return &Manager{
		bridgeName: DefaultBridgeName,
		bridgeCIDR: DefaultBridgeCIDR,
	}
}

// EnsureBridge initializes the host software bridge and configures NAT forwarding.
func (m *Manager) EnsureBridge() (*netlink.Bridge, error) {
	link, err := netlink.LinkByName(m.bridgeName)
	if err == nil {
		if br, ok := link.(*netlink.Bridge); ok {
			return br, nil
		}
		return nil, fmt.Errorf("interface %s exists but is not a bridge", m.bridgeName)
	}

	la := netlink.NewLinkAttrs()
	la.Name = m.bridgeName
	br := &netlink.Bridge{LinkAttrs: la}

	if err := netlink.LinkAdd(br); err != nil {
		return nil, fmt.Errorf("failed to create bridge %s: %w", m.bridgeName, err)
	}

	addr, err := netlink.ParseAddr(m.bridgeCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bridge CIDR %s: %w", m.bridgeCIDR, err)
	}

	if err := netlink.AddrAdd(br, addr); err != nil {
		return nil, fmt.Errorf("failed to assign IP to bridge %s: %w", m.bridgeName, err)
	}

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, fmt.Errorf("failed to bring bridge %s UP: %w", m.bridgeName, err)
	}

	// Enable host kernel IPv4 forwarding
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)

	// Configure iptables MASQUERADE for outbound internet traffic
	_ = exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "10.200.0.0/24", "!", "-o", m.bridgeName, "-j", "MASQUERADE").Run()
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.200.0.0/24", "!", "-o", m.bridgeName, "-j", "MASQUERADE").Run(); err != nil {
		// Non-fatal if iptables rule exists or is managed by external firewall
	}

	return br, nil
}

// SetupContainerNetwork provisions a veth pair, attaches host end to bridge,
// moves container end into child PID's netns, and sets up routes and DNS.
func (m *Manager) SetupContainerNetwork(containerID string, pid int, rootfs string) error {
	br, err := m.EnsureBridge()
	if err != nil {
		return fmt.Errorf("failed to ensure bridge: %w", err)
	}

	// Generate deterministic short interface name for host side: veth<shortID>
	hash := sha256.Sum256([]byte(containerID))
	shortID := hex.EncodeToString(hash[:])[:7]
	vethHostName := "veth" + shortID
	vethPeerName := "ceth" + shortID

	// Clean up previous stale link if exists
	if oldLink, err := netlink.LinkByName(vethHostName); err == nil {
		_ = netlink.LinkDel(oldLink)
	}

	vethAttrs := netlink.NewLinkAttrs()
	vethAttrs.Name = vethHostName
	vethAttrs.MasterIndex = br.Index

	veth := &netlink.Veth{
		LinkAttrs: vethAttrs,
		PeerName:  vethPeerName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair (%s <-> %s): %w", vethHostName, vethPeerName, err)
	}

	if err := netlink.LinkSetUp(veth); err != nil {
		return fmt.Errorf("failed to bring host veth %s UP: %w", vethHostName, err)
	}

	peerLink, err := netlink.LinkByName(vethPeerName)
	if err != nil {
		return fmt.Errorf("failed to locate peer veth %s: %w", vethPeerName, err)
	}

	// Move the container end into the child's network namespace
	if err := netlink.LinkSetNsPid(peerLink, pid); err != nil {
		_ = netlink.LinkDel(veth)
		return fmt.Errorf("failed to move peer veth into pid %d netns: %w", pid, err)
	}

	// Compute deterministic container IP based on short ID hash (range: 2 to 254)
	ipSuffix := (int(hash[0]) % 252) + 2
	containerIP := fmt.Sprintf("%s%d/24", DefaultSubnetIP, ipSuffix)

	// Configure inside the container's network namespace
	if err := configureInNetns(pid, vethPeerName, containerIP, "10.200.0.1"); err != nil {
		_ = netlink.LinkDel(veth)
		return fmt.Errorf("failed to configure network inside container netns: %w", err)
	}

	// Inject trusted DNS into container rootfs
	if rootfs != "" {
		_ = injectResolvConf(rootfs)
	}

	return nil
}

// configureInNetns executes link setup and default route inside the child namespace.
func configureInNetns(pid int, peerName, containerCIDR, gatewayIP string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get host netns: %w", err)
	}
	defer func() {
		_ = netns.Set(hostNs)
		_ = hostNs.Close()
	}()

	childNs, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("failed to get child netns from pid %d: %w", pid, err)
	}
	defer childNs.Close()

	if err := netns.Set(childNs); err != nil {
		return fmt.Errorf("failed to switch to child netns: %w", err)
	}

	// Bring up loopback interface
	if loLink, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(loLink)
	}

	// Locate moved peer interface
	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		return fmt.Errorf("failed to find %s inside child netns: %w", peerName, err)
	}

	// Rename inside container to standard eth0
	if err := netlink.LinkSetName(peerLink, "eth0"); err != nil {
		return fmt.Errorf("failed to rename %s to eth0: %w", peerName, err)
	}

	eth0, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("failed to find eth0: %w", err)
	}

	addr, err := netlink.ParseAddr(containerCIDR)
	if err != nil {
		return fmt.Errorf("invalid container CIDR %s: %w", containerCIDR, err)
	}

	if err := netlink.AddrAdd(eth0, addr); err != nil {
		return fmt.Errorf("failed to add address %s to eth0: %w", containerCIDR, err)
	}

	if err := netlink.LinkSetUp(eth0); err != nil {
		return fmt.Errorf("failed to set eth0 UP: %w", err)
	}

	// Add default gateway route (0.0.0.0/0 -> 10.200.0.1)
	gw := net.ParseIP(gatewayIP)
	if gw == nil {
		return fmt.Errorf("invalid gateway IP: %s", gatewayIP)
	}

	defaultRoute := &netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: eth0.Attrs().Index,
		Gw:        gw,
	}

	if err := netlink.RouteAdd(defaultRoute); err != nil {
		return fmt.Errorf("failed to add default route to %s: %w", gatewayIP, err)
	}

	return nil
}

// injectResolvConf writes reliable fallback DNS resolvers into the container rootfs.
func injectResolvConf(rootfs string) error {
	etcDir := filepath.Join(rootfs, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		return err
	}

	resolvPath := filepath.Join(etcDir, "resolv.conf")
	data := "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	return os.WriteFile(resolvPath, []byte(data), 0644)
}

// CleanupHostInterface removes the host-side veth device when container terminates.
func (m *Manager) CleanupHostInterface(containerID string) {
	hash := sha256.Sum256([]byte(containerID))
	shortID := hex.EncodeToString(hash[:])[:7]
	vethHostName := "veth" + shortID

	if link, err := netlink.LinkByName(vethHostName); err == nil {
		_ = netlink.LinkDel(link)
	}
}
