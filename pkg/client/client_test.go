package client

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arkrix/gojail/pkg/server"
)

func TestClient_Run(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gojail-client-test-*")
	if err != nil {
		t.Fatalf("failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "test.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to create mock unix listener: %v", err)
	}
	defer listener.Close()

	// Mock server worker
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		var req server.Request
		if decErr := json.NewDecoder(conn).Decode(&req); decErr != nil {
			return
		}

		resp := server.Response{
			ExitCode: 0,
			Stdout:   "echo: " + req.Command,
			Duration: 5 * time.Millisecond,
			TimedOut: false,
		}
		_ = json.NewEncoder(conn).Encode(resp)
	}()

	c := NewClient(sockPath)
	res, err := c.Run(ExecOptions{
		Command: "/bin/echo",
		Args:    []string{"hello"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("client.Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if res.Stdout != "echo: /bin/echo" {
		t.Errorf("unexpected stdout: %s", res.Stdout)
	}
}

func TestClient_ConnectionRefused(t *testing.T) {
	c := NewClient("/tmp/non_existent_gojail.sock")
	_, err := c.Run(ExecOptions{Command: "/bin/sh"})
	if err == nil {
		t.Fatal("expected error connecting to non-existent socket, got nil")
	}
}
