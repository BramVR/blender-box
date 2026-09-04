package cli

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windows"
)

type RunService interface {
	Plan(orchestrator.PlanIntent) (orchestrator.PlanResult, error)
	Doctor(context.Context, orchestrator.PlanIntent) (orchestrator.DoctorResult, error)
	Run(context.Context, orchestrator.RunIntent) (orchestrator.RunResult, error)
	Status(context.Context, target.Target, orchestrator.RunID) (orchestrator.StatusResult, error)
	Stop(context.Context, target.Target, orchestrator.RunID) (orchestrator.StopResult, error)
}

type HostService interface {
	Run(context.Context, []string, io.Reader, io.Writer, io.Writer) int
}

type Dependencies struct {
	SSH           windows.SetupSSH
	Runner        RunService
	Now           func() time.Time
	NewIdentities func() (orchestrator.RunID, orchestrator.RequestID, string, error)
	Host          HostService
}

func Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "plan":
		return planCommand(args[1:], stdout, stderr, dependencies)
	case "doctor":
		return doctorCommand(ctx, args[1:], stdout, stderr, dependencies)
	case "run":
		return runCommand(ctx, args[1:], stdout, stderr, dependencies)
	case "status":
		return statusCommand(ctx, args[1:], stdout, stderr, dependencies)
	case "stop":
		return stopCommand(ctx, args[1:], stdout, stderr, dependencies)
	case "host":
		if dependencies.Host == nil {
			return fail(stderr, "host command", fmt.Errorf("host service is unavailable"))
		}
		return dependencies.Host.Run(ctx, args[1:], stdin, stdout, stderr)
	case "windows":
		if len(args) >= 2 && args[1] == "check" {
			return windowsCheckCommand(ctx, args[2:], stdout, stderr, dependencies)
		}
		if len(args) >= 2 && args[1] == "setup" {
			return windowsSetupCommand(ctx, args[2:], stdout, stderr, dependencies)
		}
	}
	printUsage(stderr)
	return 2
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  blender-box plan --target PATH --payload PATH [--json]")
	fmt.Fprintln(output, "  blender-box doctor --target PATH --payload PATH [--timeout 2m] [--json]")
	fmt.Fprintln(output, "  blender-box windows check --target PATH [--json]")
	fmt.Fprintln(output, "  blender-box windows setup --target PATH --host-binary PATH [--apply] [--json]")
	fmt.Fprintln(output, "  blender-box run --target PATH --payload PATH [--evidence-dir PATH] [--timeout 15m] [--json]")
	fmt.Fprintln(output, "  blender-box status --target PATH --run RUN_ID [--timeout 2m] [--json]")
	fmt.Fprintln(output, "  blender-box stop --target PATH --run RUN_ID [--timeout 2m] [--json]")
}

func doctorCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	targetPath := flags.String("target", "", "path to target JSON")
	payloadPath := flags.String("payload", "", "path to Run Payload JSON")
	timeout := flags.Duration("timeout", 2*time.Minute, "host inspection timeout")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *targetPath == "" || *payloadPath == "" || *timeout <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "doctor requires --target PATH and --payload PATH; --timeout must be positive")
		return 2
	}
	selected, err := target.Load(*targetPath)
	if err != nil {
		return fail(stderr, "load target", err)
	}
	loaded, err := payload.Load(*payloadPath)
	if err != nil {
		return fail(stderr, "load payload", err)
	}
	if dependencies.Runner == nil {
		return fail(stderr, "doctor", fmt.Errorf("Run service is unavailable"))
	}
	requestCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := dependencies.Runner.Doctor(requestCtx, orchestrator.PlanIntent{Target: selected, Payload: loaded})
	if err != nil {
		return fail(stderr, "doctor", err)
	}
	if *asJSON {
		if exitCode := writeJSON(stdout, stderr, result); exitCode != 0 {
			return exitCode
		}
	} else {
		fmt.Fprintf(stdout, "Doctor: %s\n", result.Status)
	}
	if result.Status != "pass" {
		return 1
	}
	return 0
}

func planCommand(args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	targetPath := flags.String("target", "", "path to target JSON")
	payloadPath := flags.String("payload", "", "path to Run Payload JSON")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *targetPath == "" || *payloadPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "plan requires --target PATH and --payload PATH")
		return 2
	}
	selected, err := target.Load(*targetPath)
	if err != nil {
		return fail(stderr, "load target", err)
	}
	loaded, err := payload.Load(*payloadPath)
	if err != nil {
		return fail(stderr, "load payload", err)
	}
	if dependencies.Runner == nil {
		return fail(stderr, "plan", fmt.Errorf("Run service is unavailable"))
	}
	result, err := dependencies.Runner.Plan(orchestrator.PlanIntent{Target: selected, Payload: loaded})
	if err != nil {
		return fail(stderr, "plan", err)
	}
	if *asJSON {
		return writeJSON(stdout, stderr, result)
	}
	fmt.Fprintf(stdout, "Plan: %s\n", result.Status)
	fmt.Fprintf(stdout, "Captures: %d\n", len(result.Captures))
	return 0
}

func windowsSetupCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("windows setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	targetPath := flags.String("target", "", "path to target JSON")
	hostBinary := flags.String("host-binary", "", "path to the Windows blender-box executable")
	apply := flags.Bool("apply", false, "install the bounded host binary and exact Scheduled Task")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *targetPath == "" || *hostBinary == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "windows setup requires --target PATH and --host-binary PATH")
		return 2
	}
	selected, err := target.Load(*targetPath)
	if err != nil {
		return fail(stderr, "load target", err)
	}
	result, err := windows.Setup(ctx, dependencies.SSH, selected, *hostBinary, *apply)
	if err != nil {
		return fail(stderr, "Windows setup", err)
	}
	if *asJSON {
		return writeJSON(stdout, stderr, result)
	}
	fmt.Fprintf(stdout, "Windows setup: %s\n", result.Status)
	fmt.Fprintf(stdout, "Host binary: %d bytes, SHA-256 %s\n", result.HostSize, result.HostSHA256)
	if !result.Applied {
		fmt.Fprintln(stdout, "No remote changes made; pass --apply to install.")
	}
	return 0
}

func windowsCheckCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("windows check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	targetPath := flags.String("target", "", "path to target JSON")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *targetPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "windows check requires --target PATH")
		return 2
	}
	selected, err := target.Load(*targetPath)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: %v\n", err)
		return 1
	}
	if dependencies.SSH == nil {
		fmt.Fprintln(stderr, "ERROR: SSH transport is unavailable")
		return 1
	}
	result, err := windows.Check(ctx, dependencies.SSH, selected)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: %v\n", err)
		return 1
	}
	if *asJSON {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: encode check result: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(encoded))
	} else {
		fmt.Fprintf(stdout, "Windows check: %s\n", result.Status)
	}
	if result.Status != "pass" {
		return 1
	}
	return 0
}

func runCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	targetPath := flags.String("target", "", "path to target JSON")
	payloadPath := flags.String("payload", "", "path to Run Payload JSON")
	evidenceDir := flags.String("evidence-dir", "", "new directory for the Evidence Bundle")
	timeout := flags.Duration("timeout", 15*time.Minute, "Run deadline from now")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *targetPath == "" || *payloadPath == "" || *timeout <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "run requires --target PATH and --payload PATH; --timeout must be positive")
		return 2
	}
	runID, requestID, controllerID, err := identities(dependencies)
	if err != nil {
		return fail(stderr, "create Run identity", err)
	}
	fmt.Fprintf(stderr, "RUN_ID=%s\n", runID)
	selected, err := target.Load(*targetPath)
	if err != nil {
		return failRunResult(stdout, stderr, *asJSON, orchestrator.RunResult{SchemaVersion: 1, RunID: runID, State: orchestrator.StateFailed, Error: err.Error()}, err)
	}
	loaded, err := payload.Load(*payloadPath)
	if err != nil {
		return failRunResult(stdout, stderr, *asJSON, orchestrator.RunResult{SchemaVersion: 1, RunID: runID, State: orchestrator.StateFailed, Error: err.Error()}, err)
	}
	if dependencies.Runner == nil {
		err := fmt.Errorf("Run service is unavailable")
		return failRunResult(stdout, stderr, *asJSON, orchestrator.RunResult{SchemaVersion: 1, RunID: runID, State: orchestrator.StateFailed, Error: err.Error()}, err)
	}
	root := *evidenceDir
	if root == "" {
		root = filepath.Join("artifacts", "blender-box", string(runID))
	}
	now := time.Now()
	if dependencies.Now != nil {
		now = dependencies.Now()
	}
	result, err := dependencies.Runner.Run(ctx, orchestrator.RunIntent{
		RunID:        runID,
		RequestID:    requestID,
		ControllerID: controllerID,
		Deadline:     now.Add(*timeout),
		Target:       selected,
		Payload:      loaded,
		EvidenceDir:  root,
	})
	if err != nil {
		failure := orchestrator.RunResult{SchemaVersion: 1, RunID: runID, State: orchestrator.StateFailed, Error: err.Error()}
		if *asJSON && !orchestrator.IsPreflightError(err) {
			recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if status, statusErr := dependencies.Runner.Status(recoveryCtx, selected, runID); statusErr == nil {
				failure = runResultFromStatus(status)
				if failure.State == orchestrator.StateComplete {
					failure.State = orchestrator.StateFailed
				}
				failure.Error = err.Error()
			}
		}
		return failRunResult(stdout, stderr, *asJSON, failure, err)
	}
	if *asJSON {
		return writeJSON(stdout, stderr, result)
	}
	fmt.Fprintf(stdout, "Run %s: %s\n", result.RunID, result.State)
	fmt.Fprintf(stdout, "Session: %s\n", result.SessionID)
	fmt.Fprintf(stdout, "Evidence: %s\n", root)
	fmt.Fprintln(stdout, "Cleanup: known")
	return 0
}

func statusCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	targetPath := flags.String("target", "", "path to target JSON")
	runID := flags.String("run", "", "exact Run ID")
	timeout := flags.Duration("timeout", 2*time.Minute, "status request timeout")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *targetPath == "" || *runID == "" || *timeout <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "status requires --target PATH and --run RUN_ID; --timeout must be positive")
		return 2
	}
	selected, err := target.Load(*targetPath)
	if err != nil {
		return failRun(stderr, orchestrator.RunID(*runID), err)
	}
	if dependencies.Runner == nil {
		return failRun(stderr, orchestrator.RunID(*runID), fmt.Errorf("Run service is unavailable"))
	}
	requestCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := dependencies.Runner.Status(requestCtx, selected, orchestrator.RunID(*runID))
	if err != nil {
		return failRun(stderr, orchestrator.RunID(*runID), err)
	}
	if *asJSON {
		return writeJSON(stdout, stderr, result)
	}
	fmt.Fprintf(stdout, "Run %s: %s\n", result.RunID, result.State)
	if result.SessionID != "" {
		fmt.Fprintf(stdout, "Session: %s\n", result.SessionID)
	}
	return 0
}

func stopCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("stop", flag.ContinueOnError)
	flags.SetOutput(stderr)
	targetPath := flags.String("target", "", "path to target JSON")
	runID := flags.String("run", "", "exact Run ID")
	timeout := flags.Duration("timeout", 2*time.Minute, "receipt lookup timeout")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *targetPath == "" || *runID == "" || *timeout <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "stop requires --target PATH and --run RUN_ID; --timeout must be positive")
		return 2
	}
	selected, err := target.Load(*targetPath)
	if err != nil {
		return failRun(stderr, orchestrator.RunID(*runID), err)
	}
	if dependencies.Runner == nil {
		return failRun(stderr, orchestrator.RunID(*runID), fmt.Errorf("Run service is unavailable"))
	}
	requestCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := dependencies.Runner.Stop(requestCtx, selected, orchestrator.RunID(*runID))
	if err != nil {
		return failRun(stderr, orchestrator.RunID(*runID), err)
	}
	if *asJSON {
		return writeJSON(stdout, stderr, result)
	}
	fmt.Fprintf(stdout, "Run %s: %s\n", result.RunID, result.Status)
	if result.SessionID != "" {
		fmt.Fprintf(stdout, "Session: %s\n", result.SessionID)
	}
	fmt.Fprintln(stdout, "Cleanup: known")
	return 0
}

func identities(dependencies Dependencies) (orchestrator.RunID, orchestrator.RequestID, string, error) {
	if dependencies.NewIdentities != nil {
		return dependencies.NewIdentities()
	}
	runID, err := randomID("bbx_")
	if err != nil {
		return "", "", "", err
	}
	requestID, err := randomID("req_")
	if err != nil {
		return "", "", "", err
	}
	controllerID, err := randomID("ctl_")
	return orchestrator.RunID(runID), orchestrator.RequestID(requestID), controllerID, err
}

func randomID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(cryptorand.Reader, value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}

func writeJSON(stdout io.Writer, stderr io.Writer, value any) int {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fail(stderr, "encode result", err)
	}
	fmt.Fprintln(stdout, string(encoded))
	return 0
}

func fail(output io.Writer, action string, err error) int {
	fmt.Fprintf(output, "ERROR: %s: %v\n", action, err)
	return 1
}

func failRun(output io.Writer, runID orchestrator.RunID, err error) int {
	fmt.Fprintf(output, "ERROR [%s]: %v\n", runID, err)
	return 1
}

func failRunResult(stdout, stderr io.Writer, asJSON bool, result orchestrator.RunResult, err error) int {
	if asJSON {
		if exitCode := writeJSON(stdout, stderr, result); exitCode != 0 {
			return exitCode
		}
	}
	return failRun(stderr, result.RunID, err)
}

func runResultFromStatus(status orchestrator.StatusResult) orchestrator.RunResult {
	return orchestrator.RunResult{
		SchemaVersion: status.SchemaVersion,
		RunID:         status.RunID,
		RequestID:     status.RequestID,
		RequestHash:   status.RequestHash,
		Deadline:      status.Deadline,
		SessionID:     status.SessionID,
		State:         status.State,
		Evidence:      status.Evidence,
		Cleanup:       status.Cleanup,
		Error:         status.Error,
	}
}
