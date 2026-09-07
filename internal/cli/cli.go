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

	linuxhost "github.com/BramVR/blender-box/internal/linux"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windows"
	"github.com/BramVR/blender-box/internal/windowsinstall"
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
	PreviewSSH    func(context.Context, windowsinstall.SSHPreparationRequest) (windowsinstall.SSHPreparationPreviewResult, error)
	Setup         windowsinstall.Executor
	SSH           windows.SetupSSH
	Runner        RunService
	RunnerFor     func(target.Target) RunService
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
	case "pair":
		return pairCommand(ctx, args[1:], stdout, stderr, dependencies)
	case "setup":
		return setupCommand(ctx, args[1:], stdout, stderr, dependencies)
	case "targets":
		return targetsCommand(args[1:], stdout, stderr)
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
	case "linux":
		if len(args) >= 2 && (args[1] == "check" || args[1] == "setup") {
			return linuxCommand(ctx, args[1], args[2:], stdout, stderr, dependencies)
		}
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
	fmt.Fprintln(output, "  blender-box setup ssh --request PATH [--json]")
	fmt.Fprintln(output, "  blender-box pair prepare|complete|status NAME [--help]")
	fmt.Fprintln(output, "  blender-box setup inspect|install|remove --platform windows --state-root PATH [--apply] [--json]")
	fmt.Fprintln(output, "  blender-box setup manifest --host-binary PATH --broker-launcher PATH --daemon-wheel PATH --source-commit SHA --daemon-source-commit SHA --patch-sha256 SHA --recipe-sha256 SHA --out PATH")
	fmt.Fprintln(output, "  blender-box targets import NAME --file PATH [--replace] [--json]\n  blender-box targets list [--json]\n  blender-box targets show NAME [--json]\n  blender-box targets forget NAME [--json]")
	fmt.Fprintln(output, "  blender-box linux check (--target PATH | --target-name NAME) [--json]\n  blender-box linux setup (--target PATH | --target-name NAME) --host-binary PATH [--apply] [--json]")
	fmt.Fprintln(output, "  blender-box windows check (--target PATH | --target-name NAME) [--json]")
	fmt.Fprintln(output, "  blender-box windows setup (--target PATH | --target-name NAME) --host-binary PATH [--apply] [--json]")
	fmt.Fprintln(output, "  blender-box run (--target PATH | --target-name NAME) --payload PATH [--evidence-dir PATH] [--timeout 15m] [--json]")
	fmt.Fprintln(output, "  blender-box status (--target PATH | --target-name NAME) --run RUN_ID [--timeout 2m] [--json]")
	fmt.Fprintln(output, "  blender-box stop (--target PATH | --target-name NAME) --run RUN_ID [--timeout 2m] [--json]")
	fmt.Fprintln(output, "  blender-box plan (--target PATH | --target-name NAME) --payload PATH [--json]")
	fmt.Fprintln(output, "  blender-box doctor (--target PATH | --target-name NAME) --payload PATH [--timeout 2m] [--json]")
}

func doctorCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	selection := targetFlags(flags)
	payloadPath := flags.String("payload", "", "path to Run Payload JSON")
	timeout := flags.Duration("timeout", 2*time.Minute, "host inspection timeout")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !selection.valid(flags) || *payloadPath == "" || *timeout <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "doctor requires exactly one of --target PATH or --target-name NAME and --payload PATH; --timeout must be positive")
		return 2
	}
	selected, err := selection.resolve()
	if err != nil {
		return fail(stderr, "load target", err)
	}
	loaded, err := payload.Load(*payloadPath)
	if err != nil {
		return fail(stderr, "load payload", err)
	}
	runner := dependencies.Runner
	if runner == nil && dependencies.RunnerFor != nil {
		runner = dependencies.RunnerFor(selected)
	}
	if runner == nil {
		return fail(stderr, "doctor", fmt.Errorf("Run service is unavailable"))
	}
	requestCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := runner.Doctor(requestCtx, orchestrator.PlanIntent{Target: selected, Payload: loaded})
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
	selection := targetFlags(flags)
	payloadPath := flags.String("payload", "", "path to Run Payload JSON")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !selection.valid(flags) || *payloadPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "plan requires exactly one of --target PATH or --target-name NAME and --payload PATH")
		return 2
	}
	selected, err := selection.resolve()
	if err != nil {
		return fail(stderr, "load target", err)
	}
	loaded, err := payload.Load(*payloadPath)
	if err != nil {
		return fail(stderr, "load payload", err)
	}
	runner := dependencies.Runner
	if runner == nil && dependencies.RunnerFor != nil {
		runner = dependencies.RunnerFor(selected)
	}
	if runner == nil {
		return fail(stderr, "plan", fmt.Errorf("Run service is unavailable"))
	}
	result, err := runner.Plan(orchestrator.PlanIntent{Target: selected, Payload: loaded})
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
	selection := targetFlags(flags)
	hostBinary := flags.String("host-binary", "", "path to the Windows blender-box executable")
	apply := flags.Bool("apply", false, "legacy apply is refused; use setup install")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !selection.valid(flags) || *hostBinary == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "windows setup requires exactly one of --target PATH or --target-name NAME and --host-binary PATH")
		return 2
	}
	selected, err := selection.resolve()
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
		fmt.Fprintln(stdout, "No remote changes made; use setup install with an owned runtime manifest.")
	}
	return 0
}

func windowsCheckCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("windows check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	selection := targetFlags(flags)
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !selection.valid(flags) || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "windows check requires exactly one of --target PATH or --target-name NAME")
		return 2
	}
	selected, err := selection.resolve()
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
	selection := targetFlags(flags)
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
	if !selection.valid(flags) || *payloadPath == "" || *timeout <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "run requires exactly one of --target PATH or --target-name NAME and --payload PATH; --timeout must be positive")
		return 2
	}
	runID, requestID, controllerID, err := identities(dependencies)
	if err != nil {
		return fail(stderr, "create Run identity", err)
	}
	fmt.Fprintf(stderr, "RUN_ID=%s\n", runID)
	selected, err := selection.resolve()
	if err != nil {
		return failRunResult(stdout, stderr, *asJSON, orchestrator.RunResult{SchemaVersion: 1, RunID: runID, State: orchestrator.StateFailed, Error: err.Error()}, err)
	}
	loaded, err := payload.Load(*payloadPath)
	if err != nil {
		return failRunResult(stdout, stderr, *asJSON, orchestrator.RunResult{SchemaVersion: 1, RunID: runID, State: orchestrator.StateFailed, Error: err.Error()}, err)
	}
	runner := dependencies.Runner
	if runner == nil && dependencies.RunnerFor != nil {
		runner = dependencies.RunnerFor(selected)
	}
	if runner == nil {
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
	result, err := runner.Run(ctx, orchestrator.RunIntent{
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
		hasUIResult := loaded.Scenario.UIActions != nil && result.RunID != ""
		if hasUIResult {
			failure = result
			if failure.State == orchestrator.StateComplete {
				failure.State = orchestrator.StateFailed
			}
			failure.Error = err.Error()
		}
		if *asJSON && !hasUIResult && !orchestrator.IsPreflightError(err) && !orchestrator.IsAuthorityError(err) {
			recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if status, statusErr := runner.Status(recoveryCtx, selected, runID); statusErr == nil {
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
	selection := targetFlags(flags)
	runID := flags.String("run", "", "exact Run ID")
	timeout := flags.Duration("timeout", 2*time.Minute, "status request timeout")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !selection.valid(flags) || *runID == "" || *timeout <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "status requires exactly one of --target PATH or --target-name NAME and --run RUN_ID; --timeout must be positive")
		return 2
	}
	selected, err := selection.resolve()
	if err != nil {
		return failRun(stderr, orchestrator.RunID(*runID), err)
	}
	runner := dependencies.Runner
	if runner == nil && dependencies.RunnerFor != nil {
		runner = dependencies.RunnerFor(selected)
	}
	if runner == nil {
		return failRun(stderr, orchestrator.RunID(*runID), fmt.Errorf("Run service is unavailable"))
	}
	requestCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := runner.Status(requestCtx, selected, orchestrator.RunID(*runID))
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
	selection := targetFlags(flags)
	runID := flags.String("run", "", "exact Run ID")
	timeout := flags.Duration("timeout", 2*time.Minute, "receipt lookup timeout")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !selection.valid(flags) || *runID == "" || *timeout <= 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "stop requires exactly one of --target PATH or --target-name NAME and --run RUN_ID; --timeout must be positive")
		return 2
	}
	selected, err := selection.resolve()
	if err != nil {
		return failRun(stderr, orchestrator.RunID(*runID), err)
	}
	runner := dependencies.Runner
	if runner == nil && dependencies.RunnerFor != nil {
		runner = dependencies.RunnerFor(selected)
	}
	if runner == nil {
		return failRun(stderr, orchestrator.RunID(*runID), fmt.Errorf("Run service is unavailable"))
	}
	requestCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := runner.Stop(requestCtx, selected, orchestrator.RunID(*runID))
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
		UIActions:     status.UIActions,
	}
}

func linuxCommand(ctx context.Context, operation string, args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("linux "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	selection := targetFlags(flags)
	asJSON := flags.Bool("json", false, "print versioned JSON")
	var hostBinary *string
	var apply *bool
	if operation == "setup" {
		hostBinary = flags.String("host-binary", "", "path to the Linux blender-box executable")
		apply = flags.Bool("apply", false, "publish managed binary, state and static user unit")
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !selection.valid(flags) || flags.NArg() != 0 || (operation == "setup" && *hostBinary == "") {
		fmt.Fprintln(stderr, "linux "+operation+" requires exactly one of --target PATH or --target-name NAME")
		return 2
	}
	selected, err := selection.resolve()
	if err != nil {
		return fail(stderr, "load target", err)
	}
	if operation == "setup" {
		result, err := linuxhost.Setup(ctx, dependencies.SSH, selected, *hostBinary, *apply)
		if err != nil {
			return fail(stderr, "Linux setup", err)
		}
		if *asJSON {
			return writeJSON(stdout, stderr, result)
		}
		fmt.Fprintf(stdout, "Linux setup: %s\nHost binary: %d bytes, SHA-256 %s\nUnit: %s\n", result.Status, result.HostSize, result.HostSHA256, result.UnitDestination)
		if !result.Applied {
			fmt.Fprintln(stdout, "No remote changes made; pass --apply to install.")
		}
		return 0
	}
	result, err := linuxhost.Check(ctx, dependencies.SSH, selected)
	if err != nil {
		return fail(stderr, "Linux check", err)
	}
	if *asJSON {
		if code := writeJSON(stdout, stderr, result); code != 0 {
			return code
		}
	} else {
		fmt.Fprintf(stdout, "Linux check: %s\n", result.Status)
		for _, check := range result.Checks {
			if !check.Passed {
				fmt.Fprintf(stdout, "%s: %s\n", check.ID, check.Message)
			}
		}
	}
	if result.Status != "pass" {
		return 1
	}
	return 0
}
