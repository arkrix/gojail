package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arkrix/gojail/pkg/sandbox"
	"github.com/arkrix/gojail/pkg/server"
)

func main() {
	// Re-exec child hook for namespace containment
	if len(os.Args) > 2 && os.Args[1] == "__init_child__" {
		if err := sandbox.InitChild(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error in child init: %v\n", err)
			os.Exit(1)
		}
		return
	}

	socketPath := flag.String("socket", "/var/run/gojail.sock", "Path to Unix domain socket")
	flag.Parse()

	d := server.NewDaemon(*socketPath)
	if err := d.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[gojaild] Startup error: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	fmt.Println("\n[gojaild] Shutting down...")
	d.Stop()
}
