package client

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arkrix/gojail/pkg/protocol"
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

	// Mock server that streams frames
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

		fw := protocol.NewFrameWriter(conn)
		_ = fw.WriteFrame(protocol.StreamStdout, []byte("echo: "+req.Command))
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 0,
			Duration: 5 * time.Millisecond,
			TimedOut: false,
		})
	}()

	var stdoutBuf bytes.Buffer
	c := NewClient(sockPath)
	res, err := c.Run(ExecOptions{
		Command: "/bin/echo",
		Args:    []string{"hello"},
		Timeout: 2 * time.Second,
		Stdout:  &stdoutBuf,
	})
	if err != nil {
		t.Fatalf("client.Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if stdoutBuf.String() != "echo: /bin/echo" {
		t.Errorf("unexpected stdout: %s", stdoutBuf.String())
	}
}

func TestClient_ConnectionRefused(t *testing.T) {
	c := NewClient("/tmp/non_existent_gojail.sock")
	_, err := c.Run(ExecOptions{Command: "/bin/sh"})
	if err == nil {
		t.Fatal("expected error connecting to non-existent socket, got nil")
	}
}
