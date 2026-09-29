package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeSSHMachine struct {
	current   sshdFacts
	admitting string
	rules     map[string]FirewallRule
	creates   int
	services  []string
}

func (m *fakeSSHMachine) facts(context.Context, string, string, string) (sshdFacts, error) {
	return m.current, nil
}
func (m *fakeSSHMachine) setService(_ context.Context, startType string, start bool) error {
	m.services = append(m.services, fmt.Sprintf("%s/start=%t", startType, start))
	if startType != "" {
		m.current.StartType = startType
	}
	if start {
		m.current.ServiceStatus = "Running"
	}
	return nil
}
func (m *fakeSSHMachine) rule(_ context.Context, operation string, rule FirewallRule) (bool, bool, error) {
	switch operation {
	case "create":
		m.creates++
		if _, exists := m.rules[rule.Name]; !exists {
			m.rules[rule.Name] = rule
		}
	case "delete":
		delete(m.rules, rule.Name)
	}
	current, exists := m.rules[rule.Name]
	return exists, exists && reflect.DeepEqual(current, rule), nil
}
func (m *fakeSSHMachine) admittingRule(context.Context, uint16) (string, error) {
	if m.admitting != "" {
		return m.admitting, nil
	}
	for name := range m.rules {
		return name, nil
	}
	return "", nil
}

var stockFacts = sshdFacts{ServiceStatus: "Running", StartType: "Automatic", Port: 22, PubkeyAuthentication: true, Elevated: true}
var coldFacts = sshdFacts{ServiceStatus: "Stopped", StartType: "Manual", Port: 22, PubkeyAuthentication: true, Elevated: true}

const sshTestID = InstallationID("bbxi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

func sshFixture(t *testing.T, facts sshdFacts, admitting string) (sshPreparer, *fakeSSHMachine, SSHRequest) {
	t.Helper()
	root := filepath.Join(tempRoot(t), "state")
	directory := filepath.Join(root, "installations", string(sshTestID))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	intent := installIntent{Root: root, OwnerSID: "S-1-5-21-test", SSHAlias: "test-host", WindowsUser: "test-user", Task: taskSpec{Name: "test-task", OwnerSID: "S-1-5-21-test", InstallationID: sshTestID, Executable: `C:\Box\runtime\blender-box.exe`, Directory: `C:\Box\runtime`}, Files: []File{{Path: "runtime", Kind: "directory"}}}
	receipt := installationReceipt{SchemaVersion: 1, InstallationID: sshTestID, OperationID: OperationID("bbxo_" + strings.Repeat("1", 32)), RootIdentity: "root-id", Intent: intent, IntentSHA256: objectDigest(intent), State: "installed", Files: []File{{Path: "runtime", Kind: "directory", Identity: "runtime-id"}}, TaskFingerprint: SHA256(strings.Repeat("c", 64)), Deleted: []string{}}
	if err := saveReceipt(filepath.Join(directory, "receipt.json"), &receipt, false); err != nil {
		t.Fatal(err)
	}
	machine := &fakeSSHMachine{current: facts, admitting: admitting, rules: map[string]FirewallRule{}}
	return sshPreparer{machine: machine}, machine, SSHRequest{StateRoot: root, InstallationID: sshTestID, RemoteAddresses: []string{"100.64.0.0/10"}}
}

var ownedRule = FirewallRule{Name: "BlenderBox-SSH-" + string(sshTestID), Port: 22, Program: `%SystemRoot%\System32\OpenSSH\sshd.exe`, Profiles: []string{"Domain", "Private"}, RemoteAddresses: []string{"100.64.0.0/10"}}

func sshReceiptOnDisk(t *testing.T, request SSHRequest) (sshReceipt, bool) {
	t.Helper()
	receipt, exists, err := readSSHReceipt(sshReceiptPath(request.StateRoot, request.InstallationID), request.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, exists
}

func applySSH(t *testing.T, p sshPreparer, request SSHRequest) (SSHResult, SSHRequest) {
	t.Helper()
	planned, err := p.PrepareSSH(context.Background(), request)
	if err != nil || planned.State != "planned" {
		t.Fatalf("preview=%+v err=%v", planned, err)
	}
	request.Apply, request.ExpectedPlan = true, planned.Plan.PlanSHA256
	applied, err := p.PrepareSSH(context.Background(), request)
	if err != nil || applied.State != "applied" {
		t.Fatalf("apply=%+v err=%v", applied, err)
	}
	return applied, request
}

func TestSetupSSHStockHostIsUnchanged(t *testing.T) {
	p, m, request := sshFixture(t, stockFacts, "OpenSSH-Server-In-TCP")
	for _, apply := range []bool{false, true} {
		request.Apply = apply
		request.ExpectedPlan = SHA256(strings.Repeat("0", 64))
		result, err := p.PrepareSSH(context.Background(), request)
		if err != nil || result.State != "unchanged" || result.Plan.Rule != nil || result.Plan.AdmittingRule != "OpenSSH-Server-In-TCP" || result.Plan.Account != "test-user" || result.Plan.Port != 22 {
			t.Fatalf("apply=%t result=%+v err=%v", apply, result, err)
		}
		if result.Plan.Service != (ServiceChange{PriorStatus: "Running", PriorStartType: "Automatic"}) {
			t.Fatalf("service=%+v", result.Plan.Service)
		}
	}
	if _, exists := sshReceiptOnDisk(t, request); exists || len(m.services) != 0 || m.creates != 0 || m.current != stockFacts {
		t.Fatalf("stock host was touched: receipt=%t services=%v creates=%d", exists, m.services, m.creates)
	}
	if _, err := os.Lstat(filepath.Join(request.StateRoot, ".operation.lock")); !os.IsNotExist(err) {
		t.Fatal("unchanged plan took the maintenance lock")
	}
}

func TestSetupSSHPlansServiceAndOwnedRule(t *testing.T) {
	p, m, request := sshFixture(t, coldFacts, "")
	result, err := p.PrepareSSH(context.Background(), request)
	if err != nil || result.State != "planned" || !hex64.MatchString(string(result.Plan.PlanSHA256)) || result.Plan.AdmittingRule != "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if result.Plan.Service != (ServiceChange{PriorStatus: "Stopped", PriorStartType: "Manual", Start: true, SetAutomatic: true}) || result.Plan.Rule == nil || !reflect.DeepEqual(*result.Plan.Rule, ownedRule) {
		t.Fatalf("plan=%+v rule=%+v", result.Plan, result.Plan.Rule)
	}
	request.Profiles = []string{"Public", "Domain"}
	custom, err := p.PrepareSSH(context.Background(), request)
	if err != nil || !reflect.DeepEqual(custom.Plan.Rule.Profiles, []string{"Domain", "Public"}) || custom.Plan.PlanSHA256 == result.Plan.PlanSHA256 {
		t.Fatalf("custom profiles=%+v err=%v", custom.Plan.Rule, err)
	}
	if _, exists := sshReceiptOnDisk(t, request); exists || m.current != coldFacts || len(m.rules) != 0 {
		t.Fatal("preview changed state")
	}
}

func TestSetupSSHApplyRequiresThePreviewedPlan(t *testing.T) {
	p, m, request := sshFixture(t, coldFacts, "")
	request.Apply = true
	result, err := p.PrepareSSH(context.Background(), request)
	if err == nil || result.State != "conflict" || result.Problems[0].Code != "invalid-request" {
		t.Fatalf("missing plan: result=%+v err=%v", result, err)
	}
	request.ExpectedPlan = SHA256(strings.Repeat("0", 64))
	result, err = p.PrepareSSH(context.Background(), request)
	if err == nil || result.State != "conflict" || result.Problems[0].Code != "plan-mismatch" || result.Plan.Rule == nil {
		t.Fatalf("wrong plan: result=%+v err=%v", result, err)
	}
	if _, exists := sshReceiptOnDisk(t, request); exists || m.current != coldFacts || len(m.rules) != 0 || len(m.services) != 0 {
		t.Fatal("refused apply changed state")
	}
}

func TestSetupSSHApplyRecordsPriorStateAndConverges(t *testing.T) {
	p, m, request := sshFixture(t, coldFacts, "")
	applied, request := applySSH(t, p, request)
	want := sshdFacts{ServiceStatus: "Running", StartType: "Automatic", Port: 22, PubkeyAuthentication: true, Elevated: true}
	if m.current != want || !reflect.DeepEqual(m.services, []string{"Automatic/start=true"}) || !reflect.DeepEqual(m.rules, map[string]FirewallRule{ownedRule.Name: ownedRule}) {
		t.Fatalf("host after apply: facts=%+v services=%v rules=%+v", m.current, m.services, m.rules)
	}
	receipt, exists := sshReceiptOnDisk(t, request)
	wantReceipt := sshReceipt{SchemaVersion: 1, InstallationID: sshTestID, PlanSHA256: applied.Plan.PlanSHA256, Service: ServiceChange{PriorStatus: "Stopped", PriorStartType: "Manual", Start: true, SetAutomatic: true}, Rule: &ownedRule, State: "applied"}
	if !exists || !reflect.DeepEqual(receipt, wantReceipt) {
		t.Fatalf("receipt=%+v exists=%t", receipt, exists)
	}
	again, err := p.PrepareSSH(context.Background(), request)
	if err != nil || again.State != "applied" || again.Plan.PlanSHA256 != applied.Plan.PlanSHA256 || m.creates != 1 || len(m.services) != 1 {
		t.Fatalf("re-apply=%+v err=%v creates=%d services=%v", again, err, m.creates, m.services)
	}
	request.Apply, request.ExpectedPlan = false, ""
	preview, err := p.PrepareSSH(context.Background(), request)
	if err != nil || preview.State != "applied" || preview.Plan.PlanSHA256 != applied.Plan.PlanSHA256 {
		t.Fatalf("preview after apply=%+v err=%v", preview, err)
	}
}

func TestSetupSSHApplyRetriesConvergeAfterEveryCheckpoint(t *testing.T) {
	var points []string
	p, _, request := sshFixture(t, coldFacts, "")
	p.checkpoint = func(point string) error {
		points = append(points, point)
		return nil
	}
	applied, _ := applySSH(t, p, request)
	if len(points) < 5 {
		t.Fatalf("checkpoints=%v", points)
	}
	for crash, name := range points {
		t.Run(fmt.Sprintf("%d %s", crash, strings.SplitN(name, ":", 2)[0]), func(t *testing.T) {
			p, m, request := sshFixture(t, coldFacts, "")
			request.Apply, request.ExpectedPlan = true, applied.Plan.PlanSHA256
			reached := 0
			p.checkpoint = func(string) error {
				reached++
				if reached == crash+1 {
					return errors.New("crash")
				}
				return nil
			}
			if _, err := p.PrepareSSH(context.Background(), request); err == nil {
				t.Fatal("crash was swallowed")
			}
			p.checkpoint = nil
			result, err := p.PrepareSSH(context.Background(), request)
			receipt, exists := sshReceiptOnDisk(t, request)
			if err != nil || result.State != "applied" || !exists || receipt.State != "applied" || receipt.Service.PriorStartType != "Manual" || m.creates != 1 || m.current.ServiceStatus != "Running" || m.current.StartType != "Automatic" || !reflect.DeepEqual(m.rules[ownedRule.Name], ownedRule) {
				t.Fatalf("retry=%+v err=%v receipt=%+v creates=%d facts=%+v", result, err, receipt, m.creates, m.current)
			}
		})
	}
}

func TestSetupSSHRefusalsLeaveTheHostAlone(t *testing.T) {
	noPubkey := coldFacts
	noPubkey.PubkeyAuthentication = false
	unelevated := coldFacts
	unelevated.Elevated = false
	cases := []struct {
		name, code, mention string
		facts               sshdFacts
		addresses           []string
	}{
		{"pubkey", "pubkey-authentication-disabled", "sshd_config", noPubkey, []string{"100.64.0.0/10"}},
		{"unelevated", "elevation-required", "elevated", unelevated, []string{"100.64.0.0/10"}},
		{"addresses", "remote-addresses-required", "--remote-address", coldFacts, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, m, request := sshFixture(t, tc.facts, "")
			request.RemoteAddresses = tc.addresses
			for _, apply := range []bool{false, true} {
				request.Apply = apply
				request.ExpectedPlan = SHA256(strings.Repeat("0", 64))
				result, err := p.PrepareSSH(context.Background(), request)
				if err == nil || result.State != "conflict" || len(result.Problems) != 1 || result.Problems[0].Code != tc.code || !strings.Contains(result.Problems[0].Message, tc.mention) || !strings.Contains(err.Error(), tc.code) {
					t.Fatalf("apply=%t result=%+v err=%v", apply, result, err)
				}
			}
			if _, exists := sshReceiptOnDisk(t, request); exists || m.current != tc.facts || len(m.rules) != 0 || len(m.services) != 0 {
				t.Fatal("refusal changed state")
			}
		})
	}
}

func TestSetupSSHRejectsMalformedRequests(t *testing.T) {
	p, _, valid := sshFixture(t, coldFacts, "")
	cases := map[string]func(*SSHRequest){
		"relative root":      func(r *SSHRequest) { r.StateRoot = "state" },
		"bad installation":   func(r *SSHRequest) { r.InstallationID = "bbxi_short" },
		"unknown profile":    func(r *SSHRequest) { r.Profiles = []string{"Home"} },
		"duplicate profile":  func(r *SSHRequest) { r.Profiles = []string{"Domain", "Domain"} },
		"address whitespace": func(r *SSHRequest) { r.RemoteAddresses = []string{"10.0.0.0/8 "} },
		"empty address":      func(r *SSHRequest) { r.RemoteAddresses = []string{""} },
		"bad expected plan":  func(r *SSHRequest) { r.ExpectedPlan = "abc" },
	}
	for name, mutate := range cases {
		request := valid
		mutate(&request)
		result, err := p.PrepareSSH(context.Background(), request)
		if err == nil || result.State != "conflict" || result.Problems[0].Code != "invalid-request" {
			t.Fatalf("%s: result=%+v err=%v", name, result, err)
		}
	}
}

func TestSetupSSHRemoveRestoresTheStartTypeOnlyWhileStillAutomatic(t *testing.T) {
	for _, drifted := range []string{"", "Disabled"} {
		t.Run("operator start type "+drifted, func(t *testing.T) {
			p, m, request := sshFixture(t, coldFacts, "")
			_, request = applySSH(t, p, request)
			if drifted != "" {
				m.current.StartType = drifted
			}
			m.services = nil
			request.Remove, request.Apply, request.ExpectedPlan = true, false, ""
			preview, err := p.PrepareSSH(context.Background(), request)
			wantService := ServiceChange{PriorStatus: "Stopped", PriorStartType: "Manual", SetAutomatic: drifted == ""}
			if err != nil || preview.State != "planned" || preview.Plan.Service != wantService || preview.Plan.Rule == nil || len(m.services) != 0 {
				t.Fatalf("preview=%+v err=%v services=%v", preview, err, m.services)
			}
			request.Apply = true
			removed, err := p.PrepareSSH(context.Background(), request)
			if err != nil || removed.State != "removed" || len(removed.Problems) != 0 || len(m.rules) != 0 || m.current.ServiceStatus != "Running" {
				t.Fatalf("remove=%+v err=%v rules=%v facts=%+v", removed, err, m.rules, m.current)
			}
			wantServices, wantType := []string{"Manual/start=false"}, "Manual"
			if drifted != "" {
				wantServices, wantType = nil, drifted
			}
			if !reflect.DeepEqual(m.services, wantServices) || m.current.StartType != wantType {
				t.Fatalf("services=%v start type=%s", m.services, m.current.StartType)
			}
			receipt, _ := sshReceiptOnDisk(t, request)
			again, err := p.PrepareSSH(context.Background(), request)
			if receipt.State != "removed" || err != nil || again.State != "unchanged" || len(m.services) != len(wantServices) {
				t.Fatalf("receipt=%+v repeat=%+v err=%v", receipt, again, err)
			}
		})
	}
}

func TestSetupSSHRemoveWithoutReceiptIsUnchanged(t *testing.T) {
	p, m, request := sshFixture(t, stockFacts, "OpenSSH-Server-In-TCP")
	request.Remove, request.Apply = true, true
	result, err := p.PrepareSSH(context.Background(), request)
	if err != nil || result.State != "unchanged" || len(m.services) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestSetupSSHRemoveDeletesOnlyTheExactOwnedRule(t *testing.T) {
	p, m, request := sshFixture(t, coldFacts, "")
	_, request = applySSH(t, p, request)
	modified := ownedRule
	modified.RemoteAddresses = []string{"0.0.0.0/0"}
	m.rules[ownedRule.Name] = modified
	m.services = nil
	request.Remove, request.Apply, request.ExpectedPlan = true, true, ""
	result, err := p.PrepareSSH(context.Background(), request)
	if err != nil || result.State != "removed" || result.Plan.Rule != nil || len(result.Problems) != 1 || result.Problems[0].Code != "rule-modified" || !strings.Contains(result.Problems[0].Message, ownedRule.Name) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !reflect.DeepEqual(m.rules, map[string]FirewallRule{ownedRule.Name: modified}) || !reflect.DeepEqual(m.services, []string{"Manual/start=false"}) || m.current.ServiceStatus != "Running" {
		t.Fatalf("rules=%+v services=%v facts=%+v", m.rules, m.services, m.current)
	}
	receipt, _ := sshReceiptOnDisk(t, request)
	if receipt.State != "removed" {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestSetupSSHRefusesUnderHostAuthority(t *testing.T) {
	p, m, request := sshFixture(t, coldFacts, "")
	applied, request := applySSH(t, p, request)
	before, _ := os.ReadFile(sshReceiptPath(request.StateRoot, request.InstallationID))
	if err := os.WriteFile(filepath.Join(request.StateRoot, "host-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.rules = map[string]FirewallRule{}
	for _, remove := range []bool{false, true} {
		request.Remove = remove
		if remove {
			request.ExpectedPlan = ""
		}
		result, err := p.PrepareSSH(context.Background(), request)
		if err == nil || result.State != "conflict" || result.Problems[0].Code != "maintenance-refused" || !strings.Contains(err.Error(), "host-lock.json") {
			t.Fatalf("remove=%t result=%+v err=%v", remove, result, err)
		}
	}
	after, _ := os.ReadFile(sshReceiptPath(request.StateRoot, request.InstallationID))
	if string(before) != string(after) || m.creates != 1 || len(m.services) != 1 || applied.State != "applied" {
		t.Fatalf("refused mutation changed state: creates=%d services=%v", m.creates, m.services)
	}
}
