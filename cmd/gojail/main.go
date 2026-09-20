package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/arkrix/gojail/pkg/client"
	"github.com/arkrix/gojail/pkg/sandbox"
)

type volumeFlags []string

func (v *volumeFlags) String() string {
	return fmt.Sprint(*v)
}

func (v *volumeFlags) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func parseMounts(rawMounts []string) ([]sandbox.MountSpec, error) {
	var specs []sandbox.MountSpec
	for _, m := range rawMounts {
		spec, err := sandbox.ParseMountSpec(m)
		if err != nil {
			return nil, err
		}
		specs = append(specs, *spec)
	}
	return specs, nil
}

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "__init_child__" {
		if err := sandbox.InitChild(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error in child init: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		handleRunCommand(os.Args[2:])
	case "direct":
		handleDirectCommand(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	default:
		handleDirectCommand(os.Args[1:])
	}
}

func handleRunCommand(args []string) {
	var normalizedArgs []string
	for _, a := range args {
		if a == "-it" {
			normalizedArgs = append(normalizedArgs, "-i", "-t")
		} else {
			normalizedArgs = append(normalizedArgs, a)
		}
	}

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cmdFlag := fs.String("cmd", "/bin/sh", "Command binary to execute")
	codeFlag := fs.String("c", "", "Inline command or script body")
	timeoutSec := fs.Int("timeout", 0, "Execution timeout in seconds (0 = 1 hour for interactive)")
	memMB := fs.Int64("mem", 128, "Memory ceiling in megabytes")
	procsMax := fs.Int64("procs", 64, "Maximum allowed processes")
	storageMB := fs.Int64("storage", 64, "Scratch storage ceiling in megabytes")
	showMetrics := fs.Bool("metrics", false, "Print peak memory and CPU telemetry")
	socketPath := fs.String("socket", "/var/run/gojail.sock", "Path to gojaild socket")
	interactive := fs.Bool("i", false, "Keep STDIN open")
	tty := fs.Bool("t", false, "Allocate a pseudo-TTY")
	seccompProfile := fs.String("seccomp", "", "Path to custom JSON seccomp profile")

	var volumes volumeFlags
	fs.Var(&volumes, "v", "Volume bind mount: host_dir:jail_target[:ro|rw]")
	fs.Var(&volumes, "volume", "Volume bind mount: host_dir:jail_target[:ro|rw]")

	if err := fs.Parse(normalizedArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	mountSpecs, err := parseMounts(volumes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in volume specification: %v\n", err)
		os.Exit(1)
	}

	isInteractive := *interactive && *tty
	targetCmd := *cmdFlag
	var targetArgs []string

	scriptBody := *codeFlag
	remaining := fs.Args()

	if isInteractive {
		if len(remaining) > 0 {
			targetCmd = remaining[0]
			targetArgs = remaining[1:]
		} else if scriptBody != "" {
			targetArgs = []string{"-c", scriptBody}
		} else {
			targetCmd = "/bin/sh"
			targetArgs = []string{"-i"}
		}
	} else {
		if scriptBody == "" && len(remaining) > 0 {
			scriptBody = remaining[0]
		}
		if scriptBody == "" {
			fmt.Println("Error: must provide a command body or script to execute, or use -it for interactive session")
			os.Exit(1)
		}
		targetArgs = []string{"-c", scriptBody}
	}

	timeoutDur := time.Duration(*timeoutSec) * time.Second
	if isInteractive && timeoutDur == 0 {
		timeoutDur = 1 * time.Hour
	}

	c := client.NewClient(*socketPath)

	opts := client.ExecOptions{
		Command:          targetCmd,
		Args:             targetArgs,
		Timeout:          timeoutDur,
		MemoryLimitBytes: *memMB * 1024 * 1024,
		MaxProcesses:     *procsMax,
		StorageLimitMB:   *storageMB,
		Mounts:           mountSpecs,
		TTY:              isInteractive,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		SeccompProfile:   *seccompProfile,
	}

	resp, err := c.Run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[gojail] Client error: %v\n", err)
		os.Exit(1)
	}

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "\n[gojail] Execution rejected: %s\n", resp.Error)
		os.Exit(1)
	}

	if resp.TimedOut {
		fmt.Fprintf(os.Stderr, "\n[gojail] Execution timed out after %v\n", resp.Duration)
	}

	if *showMetrics {
		peakMB := float64(resp.Metrics.PeakMemoryBytes) / (1024 * 1024)
		fmt.Fprintf(os.Stderr, "\n[Telemetry] Peak Memory: %.2f MB (%d B) | User CPU: %d µs | Sys CPU: %d µs | Wall: %v\n",
			peakMB, resp.Metrics.PeakMemoryBytes, resp.Metrics.UserCPUTimeUS, resp.Metrics.SystemCPUTimeUS, resp.Duration)
	}

	os.Exit(resp.ExitCode)
}

func handleDirectCommand(args []string) {
	fs := flag.NewFlagSet("direct", flag.ExitOnError)
	cmdFlag := fs.String("cmd", "/bin/sh", "Command binary to execute")
	codeFlag := fs.String("c", "", "Inline command or script body")
	timeoutSec := fs.Int("timeout", 5, "Execution timeout in seconds")
	memMB := fs.Int64("mem", 128, "Memory ceiling in megabytes")
	procsMax := fs.Int64("procs", 32, "Maximum allowed processes")
	storageMB := fs.Int64("storage", 64, "Storage ceiling in megabytes")
	seccompProfile := fs.String("seccomp", "", "Path to custom JSON seccomp profile")

	var volumes volumeFlags
	fs.Var(&volumes, "v", "Volume bind mount: host_dir:jail_target[:ro|rw]")
	fs.Var(&volumes, "volume", "Volume bind mount: host_dir:jail_target[:ro|rw]")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	mountSpecs, err := parseMounts(volumes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in volume specification: %v\n", err)
		os.Exit(1)
	}

	scriptBody := *codeFlag
	if scriptBody == "" && len(fs.Args()) > 0 {
		scriptBody = fs.Args()[0]
	}

	if scriptBody == "" {
		fmt.Println("Error: must provide a command via -c flag or as an argument")
		os.Exit(1)
	}

	sandboxID := fmt.Sprintf("jail-%d", time.Now().UnixNano())
	cfg := sandbox.Config{
		ID:               sandboxID,
		MemoryLimitBytes: *memMB * 1024 * 1024,
		MaxProcesses:     *procsMax,
		StorageLimitMB:   *storageMB,
		Timeout:          time.Duration(*timeoutSec) * time.Second,
		Command:          *cmdFlag,
		Args:             []string{"-c", scriptBody},
		Env:              []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"},
		Mounts:           mountSpecs,
		SeccompProfile:   *seccompProfile,
	}

	runner := sandbox.NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gojail] Direct execution error: %v\n", err)
		os.Exit(1)
	}

	if res.Stdout != "" {
		fmt.Print(res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Fprint(os.Stderr, res.Stderr)
	}

	os.Exit(res.ExitCode)
}

func printUsage() {
	fmt.Println("Usage: gojail <command> [options] [script]")
	fmt.Println("\nCommands:")
	fmt.Println("  run      Execute command via the background daemon (gojaild)")
	fmt.Println("  direct   Execute command directly using root permissions (standalone mode)")
	fmt.Println("\nOptions for run:")
	fmt.Println("  -it            Run an interactive session connected to a pseudo-TTY")
	fmt.Println("  -v, --volume   Bind mount: host:target[:ro|rw] (can be specified multiple times)")
	fmt.Println("  -mem int       Memory ceiling in MB (default 128)")
	fmt.Println("  -procs int     Max processes (default 64)")
	fmt.Println("  -storage int   Scratch storage ceiling in MB (default 64)")
	fmt.Println("  -timeout int   Timeout in seconds (default 5)")
	fmt.Println("  -metrics       Print peak memory and CPU telemetry")
	fmt.Println("  -seccomp path  Path to custom JSON seccomp profile")
}
