package sandbox

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arkrix/gojail/pkg/network"
)

func TestIntegration_NetworkModeNone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping network isolation test; root privileges required")
	}

	cfg := Config{
		ID:               fmt.Sprintf("test-net-none-%d", time.Now().UnixNano()),
		MemoryLimitBytes: 128 * 1024 * 1024,
		MaxProcesses:     32,
		StorageLimitMB:   64,
		Timeout:          5 * time.Second,
		NetworkMode:      "none",
		Command:          "/bin/sh",
		Args: []string{
			"-c",
			"ip -o link show | wc -l",
		},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("failed to run container: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", res.ExitCode, res.Stderr)
	}

	output := strings.TrimSpace(res.Stdout)
	if output != "1" {
		t.Errorf("expected exactly 1 interface (lo) in 'none' mode, got %s", output)
	}
}

func TestIntegration_NetworkModeBridge_Egress(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping bridge egress test; root privileges required")
	}

	netMgr := network.NewManager()
	if _, err := netMgr.EnsureBridge(); err != nil {
		t.Fatalf("failed to ensure bridge: %v", err)
	}

	hostListener, err := net.Listen("tcp", "10.200.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on bridge gateway: %v", err)
	}
	defer hostListener.Close()

	gatewayPort := hostListener.Addr().(*net.TCPAddr).Port

	acceptedCh := make(chan bool, 1)
	go func() {
		conn, err := hostListener.Accept()
		if err == nil {
			_ = conn.Close()
			acceptedCh <- true
		} else {
			acceptedCh <- false
		}
	}()

	cfg := Config{
		ID:               fmt.Sprintf("test-net-bridge-%d", time.Now().UnixNano()),
		MemoryLimitBytes: 128 * 1024 * 1024,
		MaxProcesses:     32,
		StorageLimitMB:   64,
		Timeout:          5 * time.Second,
		NetworkMode:      "bridge",
		Command:          "/bin/sh",
		Args: []string{
			"-c",
			fmt.Sprintf("nc -z -w 2 10.200.0.1 %d || echo 'FALLBACK' | nc -w 2 10.200.0.1 %d", gatewayPort, gatewayPort),
		},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("failed to run bridge container: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("failed to reach bridge gateway (exit %d): %s (stdout: %s)", res.ExitCode, res.Stderr, res.Stdout)
	}

	select {
	case ok := <-acceptedCh:
		if !ok {
			t.Fatal("failed to accept egress connection from container")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for egress connection from container")
	}
}

func TestIntegration_NetworkModeBridge_PortForwarding(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping port forwarding test; root privileges required")
	}

	hostPort := 18080
	containerPort := 8080

	serverScript := fmt.Sprintf(`
if command -v python3 >/dev/null 2>&1; then
    python3 -u -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', %[1]d))
s.listen(1)
conn, _ = s.accept()
conn.sendall(b'jail-ack\n')
conn.close()
s.close()
"
elif command -v nc >/dev/null 2>&1; then
    echo 'jail-ack' | nc -l -p %[1]d || echo 'jail-ack' | nc -l %[1]d
fi
`, containerPort)

	cfg := Config{
		ID:               fmt.Sprintf("test-net-dnat-%d", time.Now().UnixNano()),
		MemoryLimitBytes: 128 * 1024 * 1024,
		MaxProcesses:     32,
		StorageLimitMB:   64,
		Timeout:          8 * time.Second,
		NetworkMode:      "bridge",
		PortMappings: []network.PortMapping{
			{
				HostPort:      hostPort,
				ContainerPort: containerPort,
				Protocol:      "tcp",
			},
		},
		Command: "/bin/sh",
		Args: []string{
			"-c",
			serverScript,
		},
	}

	runner := NewRunner(cfg)

	errCh := make(chan error, 1)
	go func() {
		res, err := runner.Run()
		if err != nil {
			errCh <- err
			return
		}
		if res.ExitCode != 0 {
			errCh <- fmt.Errorf("container exited with %d: %s (stdout: %s)", res.ExitCode, res.Stderr, res.Stdout)
			return
		}
		errCh <- nil
	}()

	// Connect to the host bridge IP which forwards through DNAT to the container
	var conn net.Conn
	var dialErr error
	targetAddr := fmt.Sprintf("10.200.0.1:%d", hostPort)

	for i := 0; i < 40; i++ {
		time.Sleep(100 * time.Millisecond)
		conn, dialErr = net.DialTimeout("tcp", targetAddr, 250*time.Millisecond)
		if dialErr == nil {
			break
		}
	}

	if dialErr != nil {
		t.Fatalf("failed to connect to host port %s: %v", targetAddr, dialErr)
	}
	defer conn.Close()

	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("failed reading through forwarded port: %v", err)
	}

	received := strings.TrimSpace(string(buf[:n]))
	if received != "jail-ack" {
		t.Errorf("expected 'jail-ack', got %q", received)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("container error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for container exit")
	}
}
