package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/arkrix/gojail/pkg/client"
	"github.com/arkrix/gojail/pkg/protocol"
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
	case "ps", "list":
		handlePsCommand(os.Args[2:])
	case "stop":
		handleStopCommand(os.Args[2:])
	case "stats", "top":
		handleStatsCommand(os.Args[2:])
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

func handlePsCommand(args []string) {
	fs := flag.NewFlagSet("ps", flag.ExitOnError)
	socketPath := fs.String("socket", "/var/run/gojail.sock", "Path to gojaild socket")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	c := client.NewClient(*socketPath)
	jobs, err := c.ListJobs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying jobs from daemon: %v\n", err)
		os.Exit(1)
	}

	if len(jobs) == 0 {
		fmt.Println("No active or recent containers.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, "CONTAINER ID\tPID\tSTATUS\tMEMORY\tUPTIME\tCOMMAND")

	for _, j := range jobs {
		cmdStr := j.Command
		if len(j.Args) > 0 {
			cmdStr += " " + strings.Join(j.Args, " ")
		}
		if len(cmdStr) > 30 {
			cmdStr = cmdStr[:27] + "..."
		}

		memStr := "-"
		if j.PeakMemoryBytes > 0 {
			memStr = fmt.Sprintf("%.2f MB", float64(j.PeakMemoryBytes)/(1024*1024))
		}

		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
			j.ID,
			j.PID,
			j.Status,
			memStr,
			j.Duration.Truncate(time.Second),
			cmdStr,
		)
	}
	_ = w.Flush()
}

func handleStopCommand(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	socketPath := fs.String("socket", "/var/run/gojail.sock", "Path to gojaild socket")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	target := fs.Arg(0)
	if target == "" {
		fmt.Println("Error: must specify a container ID to stop")
		os.Exit(1)
	}

	c := client.NewClient(*socketPath)
	if err := c.StopJob(target); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping container %s: %v\n", target, err)
		os.Exit(1)
	}

	fmt.Printf("Container %s stopped successfully.\n", target)
}

func handleStatsCommand(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	socketPath := fs.String("socket", "/var/run/gojail.sock", "Path to gojaild socket")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	target := fs.Arg(0)
	if target == "" {
		fmt.Println("Error: must specify a container ID to stream stats for")
		os.Exit(1)
	}

	c := client.NewClient(*socketPath)
	headerPrinted := false

	err := c.StreamStats(target, func(s protocol.StatsPayload) {
		memMB := float64(s.MemoryBytes) / (1024 * 1024)
		peakMB := float64(s.PeakMemoryBytes) / (1024 * 1024)

		limitStr := "unlimited"
		if s.MemoryLimitBytes > 0 {
			limitStr = fmt.Sprintf("%.2f MB", float64(s.MemoryLimitBytes)/(1024*1024))
		}

		pidLimitStr := "max"
		if s.PIDsLimit > 0 {
			pidLimitStr = fmt.Sprintf("%d", s.PIDsLimit)
		}

		if !headerPrinted {
			fmt.Printf("%-24s %-10s %-20s %-12s %-12s\n", "CONTAINER ID", "CPU %", "MEM USAGE / LIMIT", "PEAK MEM", "PIDS")
			headerPrinted = true
		}

		fmt.Printf("\r%-24s %-9.2f%% %-7.2fMB / %-9s %-10.2fMB %d / %-6s",
			s.ContainerID,
			s.CPUPercent,
			memMB,
			limitStr,
			peakMB,
			s.PIDsCurrent,
			pidLimitStr,
		)
	})

	fmt.Println()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Stats stream error: %v\n", err)
		os.Exit(1)
	}
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
	fmt.Println("  run            Execute command via the background daemon (gojaild)")
	fmt.Println("  ps, list       List active and recently finished sandbox containers")
	fmt.Println("  stop <id>      Terminate an active sandbox container")
	fmt.Println("  stats <id>     Stream real-time resource utilization for an active container")
	fmt.Println("  direct         Execute command directly using root permissions (standalone mode)")
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
