package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/BramVR/blender-box/internal/windowsinstall"
)

// setupSSHCommand previews or applies the bounded OpenSSH preparation a pairing needs.
func setupSSHCommand(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("setup ssh", flag.ContinueOnError)
	flags.SetOutput(stderr)
	request := windowsinstall.SSHRequest{}
	platform := flags.String("platform", "", "host platform; windows")
	flags.StringVar(&request.StateRoot, "state-root", "", "absolute host-local shared authority root")
	var installation, expected, addresses, profiles string
	flags.StringVar(&installation, "installation", "", "installed installation ID")
	flags.StringVar(&addresses, "remote-address", "", "comma-separated remote addresses or prefixes an owned firewall rule admits")
	flags.StringVar(&profiles, "firewall-profile", "", "comma-separated firewall profiles for an owned rule (default Domain,Private)")
	flags.BoolVar(&request.Remove, "remove", false, "reverse an earlier apply: restore the service start type and delete the owned rule")
	flags.BoolVar(&request.Apply, "apply", false, "apply the previewed plan or removal")
	flags.StringVar(&expected, "expected-plan", "", "require preview plan SHA-256")
	asJSON := flags.Bool("json", false, "print versioned JSON including partial results")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *platform == "" || request.StateRoot == "" || installation == "" || request.Apply && !request.Remove && expected == "" {
		fmt.Fprintln(stderr, "setup ssh requires --platform, --state-root and --installation; --apply requires --expected-plan from preview")
		return 2
	}
	if *platform != "windows" {
		return fail(stderr, "setup ssh", fmt.Errorf("platform %s is unsupported; no host changes performed", *platform))
	}
	request.InstallationID = windowsinstall.InstallationID(installation)
	request.ExpectedPlan = windowsinstall.SHA256(expected)
	request.RemoteAddresses = splitList(addresses)
	request.Profiles = splitList(profiles)
	preparer := dependencies.SSHPreparer
	if preparer == nil {
		preparer = windowsinstall.NewSSHPreparer()
	}
	result, err := preparer.PrepareSSH(ctx, request)
	if *asJSON {
		if code := writeJSON(stdout, stderr, result); code != 0 {
			return code
		}
	} else {
		fmt.Fprintf(stdout, "Windows setup ssh: %s\n", result.State)
		if result.Plan.Account != "" {
			fmt.Fprintf(stdout, "Account %s; sshd port %d\n", result.Plan.Account, result.Plan.Port)
		}
		if result.Plan.PlanSHA256 != "" {
			fmt.Fprintf(stdout, "Plan SHA-256 %s\n", result.Plan.PlanSHA256)
		}
		service := result.Plan.Service
		switch {
		case request.Remove && service.SetAutomatic:
			fmt.Fprintf(stdout, "Service sshd start type restored to %s; sshd is not stopped\n", service.PriorStartType)
		case request.Remove:
			fmt.Fprintln(stdout, "Service sshd unchanged")
		case service.PriorStatus != "":
			fmt.Fprintf(stdout, "Service sshd %s, start type %s", service.PriorStatus, service.PriorStartType)
			if service.Start {
				fmt.Fprint(stdout, "; start")
			}
			if service.SetAutomatic {
				fmt.Fprint(stdout, "; set Automatic")
			}
			fmt.Fprintln(stdout)
		}
		if rule := result.Plan.Rule; rule != nil && request.Remove {
			fmt.Fprintf(stdout, "Firewall rule %s deleted\n", rule.Name)
		} else if rule != nil {
			fmt.Fprintf(stdout, "Firewall rule %s: inbound TCP %d to %s; profiles %s; remote %s\n", rule.Name, rule.Port, rule.Program, strings.Join(rule.Profiles, ","), strings.Join(rule.RemoteAddresses, ","))
		} else if result.Plan.AdmittingRule != "" {
			fmt.Fprintf(stdout, "Existing enabled inbound rule %s already admits the port; no rule created\n", result.Plan.AdmittingRule)
		}
		for _, problem := range result.Problems {
			fmt.Fprintf(stdout, "Problem %s: %s\n", problem.Code, problem.Message)
		}
		if result.State == "planned" && request.Remove {
			fmt.Fprintln(stdout, "Preview only; repeat with --remove --apply to reverse these changes.")
		} else if result.State == "planned" {
			fmt.Fprintln(stdout, "Preview only; repeat with --apply --expected-plan to make these changes.")
		}
	}
	if err != nil {
		return fail(stderr, "setup ssh", err)
	}
	return 0
}

func splitList(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}
