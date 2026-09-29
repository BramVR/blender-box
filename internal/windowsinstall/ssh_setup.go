package windowsinstall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
)

// SSHRequest is the `setup ssh` operation: preview by default, apply against an exact plan, or
// remove what an earlier apply changed. It is deliberately separate from Request.
type SSHRequest struct {
	StateRoot       string         `json:"state_root"`
	InstallationID  InstallationID `json:"installation_id"`
	RemoteAddresses []string       `json:"remote_addresses"`
	Profiles        []string       `json:"profiles"`
	Remove          bool           `json:"remove"`
	Apply           bool           `json:"apply"`
	ExpectedPlan    SHA256         `json:"expected_plan"`
}
type ServiceChange struct {
	PriorStatus    string `json:"prior_status"`
	PriorStartType string `json:"prior_start_type"`
	Start          bool   `json:"start"`
	SetAutomatic   bool   `json:"set_automatic"`
}
type FirewallRule struct {
	Name            string   `json:"name"`
	Port            uint16   `json:"port"`
	Program         string   `json:"program"`
	Profiles        []string `json:"profiles"`
	RemoteAddresses []string `json:"remote_addresses"`
}
type SSHPlan struct {
	PlanSHA256    SHA256        `json:"plan_sha256"`
	Account       string        `json:"account"`
	Port          uint16        `json:"port"`
	Service       ServiceChange `json:"service"`
	Rule          *FirewallRule `json:"rule,omitempty"`
	AdmittingRule string        `json:"admitting_rule,omitempty"`
}
type SSHResult struct {
	SchemaVersion int       `json:"schema_version"`
	State         string    `json:"state"` // planned | unchanged | applied | removed | conflict
	Plan          SSHPlan   `json:"plan"`
	Problems      []Problem `json:"problems"`
}
type SSHPreparer interface {
	PrepareSSH(context.Context, SSHRequest) (SSHResult, error)
}

// sshdProgram is the firewall program path of the Windows OpenSSH server. The stock
// OpenSSH-Server-In-TCP rule binds the same expanded path, so an owned rule stays host-portable.
const sshdProgram = `%SystemRoot%\System32\OpenSSH\sshd.exe`
const sshReceiptLimit = 1 << 20

var firewallProfiles = []string{"Domain", "Private", "Public"}

// sshMachine is the host boundary: sshd facts, one service change, one named rule, and the
// enabled inbound rule that already admits a port. Native Windows, a posix stub and a test fake
// implement it.
type sshMachine interface {
	sshdResolver
	setService(ctx context.Context, startType string, start bool) error
	// rule inspects, creates or deletes the named rule and reports whether it exists and
	// matches the given definition afterwards. Operation is inspect, create or delete.
	rule(ctx context.Context, operation string, rule FirewallRule) (exists, matches bool, err error)
	// admittingRule names an enabled inbound allow rule that admits TCP port for sshd, or "".
	admittingRule(ctx context.Context, port uint16) (string, error)
}
type sshPreparer struct {
	machine    sshMachine
	checkpoint func(string) error
}

func NewSSHPreparer() SSHPreparer { return sshPreparer{machine: nativeSSHMachine{}} }

// sshReceipt records the prior service state and the owned rule so removal reverses exactly
// what apply changed. It lives at STATE_ROOT/ssh-preparation/<installation>.json.
type sshReceipt struct {
	SchemaVersion  int            `json:"schema_version"`
	InstallationID InstallationID `json:"installation_id"`
	PlanSHA256     SHA256         `json:"plan_sha256"`
	Service        ServiceChange  `json:"service"`
	Rule           *FirewallRule  `json:"rule,omitempty"`
	State          string         `json:"state"` // applying | applied | removed
}

func (r SSHRequest) validate() error {
	if !filepath.IsAbs(r.StateRoot) || filepath.Clean(r.StateRoot) != r.StateRoot {
		return fmt.Errorf("state root must be absolute and clean")
	}
	if !installID.MatchString(string(r.InstallationID)) {
		return fmt.Errorf("invalid installation id")
	}
	seen := map[string]bool{}
	for _, profile := range r.Profiles {
		if !slices.Contains(firewallProfiles, profile) || seen[profile] {
			return fmt.Errorf("firewall profiles must be distinct Domain, Private or Public values")
		}
		seen[profile] = true
	}
	if len(r.RemoteAddresses) > 64 {
		return fmt.Errorf("too many remote addresses")
	}
	for _, address := range r.RemoteAddresses {
		if address == "" || len(address) > 64 || strings.ContainsFunc(address, unicode.IsSpace) || seen[address] {
			return fmt.Errorf("remote addresses must be distinct, non-empty and free of whitespace")
		}
		seen[address] = true
	}
	if r.ExpectedPlan != "" && !hex64.MatchString(string(r.ExpectedPlan)) {
		return fmt.Errorf("invalid expected plan hash")
	}
	if r.Apply && !r.Remove && r.ExpectedPlan == "" {
		return fmt.Errorf("apply requires the previewed plan hash")
	}
	return nil
}

func sshProblem(result SSHResult, code string, err error) (SSHResult, error) {
	result.State = "conflict"
	result.Problems = append(result.Problems, Problem{code, err.Error()})
	return result, fmt.Errorf("%s: %w", code, err)
}

func sshReceiptPath(root string, id InstallationID) string {
	return filepath.Join(root, "ssh-preparation", string(id)+".json")
}

func readSSHReceipt(path string, id InstallationID) (sshReceipt, bool, error) {
	data, err := privatefile.ReadSource(path, sshReceiptLimit)
	if os.IsNotExist(err) {
		return sshReceipt{}, false, nil
	}
	if err != nil {
		return sshReceipt{}, false, err
	}
	var receipt sshReceipt
	if err := strictjson.Decode(data, &receipt); err != nil {
		return sshReceipt{}, false, err
	}
	if receipt.SchemaVersion != 1 || receipt.InstallationID != id || !hex64.MatchString(string(receipt.PlanSHA256)) || !slices.Contains([]string{"applying", "applied", "removed"}, receipt.State) {
		return sshReceipt{}, false, fmt.Errorf("invalid ssh preparation receipt")
	}
	return receipt, true, nil
}

func (p sshPreparer) publish(path string, receipt sshReceipt, replace bool) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return publishBytes(path, directory, data, replace, p.checkpoint)
}

func (p sshPreparer) mark(point string) error {
	if p.checkpoint == nil {
		return nil
	}
	return p.checkpoint(point)
}

// PrepareSSH previews by default. Apply and removal mutate only under the shared host
// maintenance authority, so an active or unresolved Run refuses them.
func (p sshPreparer) PrepareSSH(ctx context.Context, request SSHRequest) (SSHResult, error) {
	result := SSHResult{SchemaVersion: 1, Problems: []Problem{}}
	if err := request.validate(); err != nil {
		return sshProblem(result, "invalid-request", err)
	}
	installation, err := readReceipt(filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "receipt.json"))
	if err != nil {
		return sshProblem(result, "installation-unavailable", err)
	}
	if installation.State != "installed" && !request.Remove {
		return sshProblem(result, "installation-unavailable", fmt.Errorf("installation is %s, not installed", installation.State))
	}
	facts, err := p.machine.facts(ctx, installation.Intent.WindowsUser, "localhost", "127.0.0.1")
	if err != nil {
		return sshProblem(result, "sshd-unavailable", err)
	}
	if !facts.Elevated {
		return sshProblem(result, "elevation-required", fmt.Errorf("setup ssh requires an elevated host-local session; no host changes performed"))
	}
	result.Plan = SSHPlan{Account: installation.Intent.WindowsUser, Port: facts.Port}
	recorded, exists, err := readSSHReceipt(sshReceiptPath(request.StateRoot, request.InstallationID), request.InstallationID)
	if err != nil {
		return sshProblem(result, "receipt-unreadable", err)
	}
	if request.Remove {
		return p.remove(ctx, request, result, facts, recorded, exists)
	}
	if !facts.PubkeyAuthentication {
		return sshProblem(result, "pubkey-authentication-disabled", fmt.Errorf("sshd resolves PubkeyAuthentication no for %s; setup ssh does not edit sshd_config", installation.Intent.WindowsUser))
	}
	return p.prepare(ctx, request, result, facts, recorded, exists && recorded.State != "removed")
}

// sshSteps is what apply still has to do. A live receipt with no steps left is converged.
type sshSteps struct{ service, rule bool }

// prepare plans against the recorded receipt when one is live, so a retry after a partial
// apply confirms the same hash and keeps the prior service state the first attempt observed.
func (p sshPreparer) prepare(ctx context.Context, request SSHRequest, result SSHResult, facts sshdFacts, recorded sshReceipt, live bool) (SSHResult, error) {
	plan := result.Plan
	if live {
		plan.Service, plan.Rule = recorded.Service, recorded.Rule
	} else {
		plan.Service = ServiceChange{PriorStatus: facts.ServiceStatus, PriorStartType: facts.StartType, Start: facts.ServiceStatus != "Running", SetAutomatic: facts.StartType != "Automatic"}
		admitting, err := p.machine.admittingRule(ctx, facts.Port)
		if err != nil {
			return sshProblem(result, "firewall-unavailable", err)
		}
		if admitting != "" {
			plan.AdmittingRule = admitting
		} else {
			if len(request.RemoteAddresses) == 0 {
				return sshProblem(result, "remote-addresses-required", fmt.Errorf("no enabled inbound rule admits TCP %d; pass --remote-address with the client addresses or prefixes an owned rule may admit", facts.Port))
			}
			profiles := request.Profiles
			if len(profiles) == 0 {
				profiles = []string{"Domain", "Private"}
			}
			plan.Rule = &FirewallRule{Name: "BlenderBox-SSH-" + string(request.InstallationID), Port: facts.Port, Program: sshdProgram, Profiles: canonicalProfiles(profiles), RemoteAddresses: request.RemoteAddresses}
		}
	}
	plan.PlanSHA256 = objectDigest(plan)
	result.Plan = plan
	steps := sshSteps{service: plan.Service.Start && facts.ServiceStatus != "Running" || plan.Service.SetAutomatic && facts.StartType != "Automatic"}
	if plan.Rule != nil {
		exists, matches, err := p.machine.rule(ctx, "inspect", *plan.Rule)
		if err != nil {
			return sshProblem(result, "firewall-unavailable", err)
		}
		if exists && !matches {
			return sshProblem(result, "rule-modified", fmt.Errorf("firewall rule %s exists with a different definition; remove or rename it before apply", plan.Rule.Name))
		}
		steps.rule = !exists
	}
	switch {
	case !steps.service && !steps.rule && live && recorded.State == "applied":
		result.State = "applied"
		return result, nil
	case !steps.service && !steps.rule && !live:
		result.State = "unchanged"
		return result, nil
	case !request.Apply:
		result.State = "planned"
		return result, nil
	case request.ExpectedPlan != plan.PlanSHA256:
		return sshProblem(result, "plan-mismatch", fmt.Errorf("expected plan %s does not match the current plan %s", request.ExpectedPlan, plan.PlanSHA256))
	case live && recorded.PlanSHA256 != plan.PlanSHA256:
		return sshProblem(result, "plan-mismatch", fmt.Errorf("recorded preparation %s no longer matches sshd; run setup ssh --remove first", recorded.PlanSHA256))
	}
	path := sshReceiptPath(request.StateRoot, request.InstallationID)
	receipt := sshReceipt{SchemaVersion: 1, InstallationID: request.InstallationID, PlanSHA256: plan.PlanSHA256, Service: plan.Service, Rule: plan.Rule, State: "applying"}
	var err error
	if lockErr := host.WithMaintenance(ctx, request.StateRoot, func() error {
		_, exists, readErr := readSSHReceipt(path, request.InstallationID)
		if readErr != nil {
			err = readErr
			return nil
		}
		if err = p.publish(path, receipt, exists); err != nil {
			return nil
		}
		if err = p.mark("receipt"); err != nil {
			return nil
		}
		if steps.service {
			startType := ""
			if plan.Service.SetAutomatic && facts.StartType != "Automatic" {
				startType = "Automatic"
			}
			if err = p.machine.setService(ctx, startType, plan.Service.Start && facts.ServiceStatus != "Running"); err != nil {
				return nil
			}
			if err = p.mark("service"); err != nil {
				return nil
			}
		}
		if steps.rule {
			if _, _, err = p.machine.rule(ctx, "create", *plan.Rule); err != nil {
				return nil
			}
			if err = p.mark("rule"); err != nil {
				return nil
			}
		}
		receipt.State = "applied"
		err = p.publish(path, receipt, true)
		return nil
	}); lockErr != nil {
		return sshProblem(result, "maintenance-refused", lockErr)
	}
	if err != nil {
		return sshProblem(result, "apply-failed", err)
	}
	result.State = "applied"
	return result, nil
}

// remove reports the recorded changes it will revert: Service.SetAutomatic stays set only while
// the start type is still the Automatic we set, and Rule is present only when the owned rule
// still matches its recorded definition. sshd is never stopped, because that would cut the
// operator's own session.
func (p sshPreparer) remove(ctx context.Context, request SSHRequest, result SSHResult, facts sshdFacts, recorded sshReceipt, exists bool) (SSHResult, error) {
	if !exists || recorded.State == "removed" {
		result.State = "unchanged"
		return result, nil
	}
	plan := result.Plan
	plan.Service = ServiceChange{PriorStatus: recorded.Service.PriorStatus, PriorStartType: recorded.Service.PriorStartType, SetAutomatic: recorded.Service.SetAutomatic && facts.StartType == "Automatic"}
	if recorded.Rule != nil {
		exists, matches, err := p.machine.rule(ctx, "inspect", *recorded.Rule)
		if err != nil {
			return sshProblem(result, "firewall-unavailable", err)
		}
		if exists && matches {
			plan.Rule = recorded.Rule
		} else if exists {
			result.Problems = append(result.Problems, Problem{"rule-modified", fmt.Sprintf("firewall rule %s no longer matches its recorded definition; left in place", recorded.Rule.Name)})
		}
	}
	plan.PlanSHA256 = objectDigest(plan)
	result.Plan = plan
	if !request.Apply {
		result.State = "planned"
		return result, nil
	}
	if request.ExpectedPlan != "" && request.ExpectedPlan != plan.PlanSHA256 {
		return sshProblem(result, "plan-mismatch", fmt.Errorf("expected plan %s does not match the removal plan %s", request.ExpectedPlan, plan.PlanSHA256))
	}
	path := sshReceiptPath(request.StateRoot, request.InstallationID)
	var err error
	if lockErr := host.WithMaintenance(ctx, request.StateRoot, func() error {
		if plan.Service.SetAutomatic {
			if err = p.machine.setService(ctx, recorded.Service.PriorStartType, false); err != nil {
				return nil
			}
			if err = p.mark("service"); err != nil {
				return nil
			}
		}
		if plan.Rule != nil {
			if _, _, err = p.machine.rule(ctx, "delete", *plan.Rule); err != nil {
				return nil
			}
			if err = p.mark("rule"); err != nil {
				return nil
			}
		}
		recorded.State = "removed"
		err = p.publish(path, recorded, true)
		return nil
	}); lockErr != nil {
		return sshProblem(result, "maintenance-refused", lockErr)
	}
	if err != nil {
		return sshProblem(result, "remove-failed", err)
	}
	result.State = "removed"
	return result, nil
}

func canonicalProfiles(profiles []string) []string {
	var canonical []string
	for _, profile := range firewallProfiles {
		if slices.Contains(profiles, profile) {
			canonical = append(canonical, profile)
		}
	}
	return canonical
}
