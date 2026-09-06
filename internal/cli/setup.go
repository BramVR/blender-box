package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/safepath"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windowsinstall"
)

type targetPublication = windowsinstall.Publication

func setupCommand(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Host-local Windows setup. Use an external verified bootstrap as the logged-in interactive account.\nPrerequisites: explicit CPython 3.11 through 3.14 amd64, Blender, and a dependency-free daemon wheel.\n  setup manifest --help     Build an offline runtime manifest from exact source artifacts.\n  setup inspect --help      Inspect the account, state root and executable candidates.\n  setup install --help      Preview; repeat with --apply to install the owned runtime and task.\n  setup remove --help       Preview; repeat with --apply to remove the exact installation.\n  setup status --help       Read the exact logical setup operation.\n  setup stop --help         Cancel the exact execution with --apply.\nNo setup command edits SSH configuration or starts Blender.")
		return 0
	}
	if args[0] == "manifest" {
		return setupManifestCommand(args[1:], stdout, stderr)
	}
	if args[0] != "inspect" && args[0] != "install" && args[0] != "remove" && args[0] != "status" && args[0] != "stop" {
		fmt.Fprintln(stderr, "setup requires inspect, install, remove, status, stop, or manifest")
		return 2
	}
	request := windowsinstall.Request{Operation: args[0]}
	flags := flag.NewFlagSet("setup "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&request.Platform, "platform", "", "host platform; windows")
	flags.StringVar(&request.StateRoot, "state-root", "", "absolute host-local shared authority root")
	var id, operation, expected, targetOut, saveTarget string
	flags.StringVar(&id, "installation", "", "installation ID from preview or receipt")
	asJSON := flags.Bool("json", false, "print versioned JSON including partial results")
	if request.Operation == "inspect" || request.Operation == "install" {
		flags.StringVar(&request.BlenderPath, "blender", "", "explicit Blender executable")
		flags.StringVar(&request.PythonPath, "python", "", "explicit CPython Windows executable")
	}
	if request.Operation == "install" || request.Operation == "remove" || request.Operation == "status" || request.Operation == "stop" {
		flags.StringVar(&operation, "operation", "", "operation identity from preview")
		if request.Operation != "status" {
			flags.BoolVar(&request.Apply, "apply", false, "apply this bounded install, removal or stop")
		}
		if request.Operation == "install" || request.Operation == "remove" {
			flags.StringVar(&expected, "expected-plan", "", "require preview plan SHA-256")
		}
		if request.Operation == "stop" {
			flags.StringVar(&request.ExecutionToken, "execution", "", "exact execution token from fresh setup status")
		}
	}
	if request.Operation == "install" {
		flags.StringVar(&request.RuntimePath, "runtime", "", "path to runtime manifest")
		flags.StringVar(&request.SSHAlias, "ssh-alias", "", "operator-managed SSH alias for emitted target")
		flags.StringVar(&request.WindowsUser, "windows-user", "", "interactive and SSH Windows account")
		flags.StringVar(&request.TaskName, "task-name", "", "new installation-owned Scheduled Task name")
		flags.StringVar(&targetOut, "target-out", "", "exclusively export installed schema-2 target")
		flags.StringVar(&saveTarget, "save-target", "", "save installed target under an unused local name")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || request.Platform == "" || request.StateRoot == "" || (targetOut != "" || saveTarget != "") && request.Operation != "install" || targetOut != "" && saveTarget != "" {
		fmt.Fprintln(stderr, "setup requires --platform and --state-root; target publication requires install and one destination")
		return 2
	}

	if saveTarget != "" {
		if err := target.ValidateName(saveTarget); err != nil {
			return fail(stderr, "target name", err)
		}
	}
	if targetOut != "" {
		absolute, err := filepath.Abs(targetOut)
		if err != nil {
			return fail(stderr, "target path", err)
		}
		targetOut = absolute
	}
	if targetOut != "" || saveTarget != "" {
		destination := targetOut
		if saveTarget != "" {
			root, err := target.ConfigDir()
			if err != nil {
				return fail(stderr, "target path", err)
			}
			destination = filepath.Join(root, "targets", saveTarget+".json")
		}
		root, err := setupPublicationPath(request.StateRoot)
		if err != nil {
			return fail(stderr, "state root", err)
		}
		destination, err = setupPublicationPath(destination)
		if err != nil {
			return fail(stderr, "target path", err)
		}
		rootKey := safepath.WindowsKey(root)
		pathKey := safepath.WindowsKey(destination)
		if pathKey == rootKey || strings.HasPrefix(pathKey, strings.TrimSuffix(rootKey, string(filepath.Separator))+string(filepath.Separator)) {
			return fail(stderr, "target path", fmt.Errorf("target publication must remain outside the setup state root"))
		}
	}
	request.TargetOut = targetOut
	request.SaveTarget = saveTarget
	if saveTarget != "" {
		root, _ := target.ConfigDir()
		request.TargetOut = filepath.Join(root, "targets", saveTarget+".json")
	}
	request.InstallationID = windowsinstall.InstallationID(id)
	request.OperationID = windowsinstall.OperationID(operation)
	request.ExpectedPlan = windowsinstall.SHA256(expected)
	executor := dependencies.Setup
	if executor == nil {
		executor = windowsinstall.NewLocal()
	}
	result, err := executor.Execute(ctx, request)
	publication := result.TargetPublication
	if *asJSON {
		if code := writeJSON(stdout, stderr, result); code != 0 {
			return code
		}
	} else {
		fmt.Fprintf(stdout, "Windows setup %s: %s\n", request.Operation, result.State)
		if result.InstallationID != "" {
			fmt.Fprintf(stdout, "Installation %s; operation %s\n", result.InstallationID, result.OperationID)
		}
		if result.Plan.PlanSHA256 != "" {
			fmt.Fprintf(stdout, "Plan SHA-256 %s\n", result.Plan.PlanSHA256)
		}
		for _, candidate := range result.Inspection.BlenderCandidates {
			fmt.Fprintf(stdout, "Blender %s; SHA-256 %s\n", candidate.Path, candidate.SHA256)
		}
		for _, file := range result.Plan.Files {
			fmt.Fprintf(stdout, "%s %s (%d bytes)\n", file.Kind, file.Path, file.Size)
		}
		if !request.Apply {
			fmt.Fprintln(stdout, "Preview only; no host files or tasks created.")
		}
		if publication.Status != "not-requested" {
			fmt.Fprintf(stdout, "Target publication: %s\n", publication.Status)
		}
	}
	if err != nil {
		return fail(stderr, "setup", err)
	}
	return 0
}

func setupPublicationPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(absolute)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		parent := filepath.Dir(absolute)
		if !os.IsNotExist(err) || parent == absolute {
			return "", err
		}
		missing = append(missing, filepath.Base(absolute))
		absolute = parent
	}
}

func setupManifestCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("setup manifest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	host := flags.String("host-binary", "", "Windows host executable")
	launcher := flags.String("broker-launcher", "", "native Windows daemon launcher")
	wheel := flags.String("daemon-wheel", "", "dependency-free daemon wheel")
	commit := flags.String("source-commit", "", "exact host/launcher source commit")
	daemonCommit := flags.String("daemon-source-commit", "", "exact daemon source commit")
	patch := flags.String("patch-sha256", "", "canonical daemon patch SHA-256")
	recipe := flags.String("recipe-sha256", "", "runtime build recipe SHA-256")
	output := flags.String("out", "", "new manifest output file")
	asJSON := flags.Bool("json", false, "print runtime manifest JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *host == "" || *launcher == "" || *wheel == "" || *output == "" {
		fmt.Fprintln(stderr, "manifest requires --host-binary, --broker-launcher, --daemon-wheel and --out")
		return 2
	}
	hostSource := windowsinstall.SourceProvenance{Repository: "BramVR/blender-box", SourceCommit: *commit, PatchSHA256: windowsinstall.SHA256(fmt.Sprintf("%064d", 0)), BuildRecipeSHA256: windowsinstall.SHA256(*recipe)}
	daemonSource := windowsinstall.SourceProvenance{Repository: "BramVR/blendersessiond", SourceCommit: *daemonCommit, PatchSHA256: windowsinstall.SHA256(*patch), BuildRecipeSHA256: windowsinstall.SHA256(*recipe)}
	manifest, err := windowsinstall.BuildManifest(*host, *launcher, *wheel, hostSource, daemonSource)
	if err != nil {
		return fail(stderr, "runtime manifest", err)
	}
	absolute, err := filepath.Abs(*output)
	if err != nil {
		return fail(stderr, "manifest path", err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fail(stderr, "manifest encoding", err)
	}
	if err = privatefile.Publish(filepath.Dir(absolute), filepath.Base(absolute), append(data, '\n'), false); err != nil {
		return fail(stderr, "manifest publication", err)
	}
	if *asJSON {
		return writeJSON(stdout, stderr, manifest)
	}
	fmt.Fprintf(stdout, "Runtime manifest written to %s\n", absolute)
	return 0
}
