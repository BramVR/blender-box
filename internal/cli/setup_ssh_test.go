package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/windowsinstall"
)

type sshPreparerFake struct {
	result   windowsinstall.SSHResult
	requests []windowsinstall.SSHRequest
}

func (p *sshPreparerFake) PrepareSSH(_ context.Context, request windowsinstall.SSHRequest) (windowsinstall.SSHResult, error) {
	p.requests = append(p.requests, request)
	return p.result, nil
}

func TestSetupSSHPassesBoundedRequestAndRefusesOtherPlatforms(t *testing.T) {
	rule := &windowsinstall.FirewallRule{Name: "BlenderBox-SSH-bbxi_" + strings.Repeat("a", 32), Port: 22, Program: `C:\Windows\System32\OpenSSH\sshd.exe`, Profiles: []string{"Domain", "Private"}, RemoteAddresses: []string{"100.64.0.0/10"}}
	preparer := &sshPreparerFake{result: windowsinstall.SSHResult{SchemaVersion: 1, State: "planned", Plan: windowsinstall.SSHPlan{PlanSHA256: windowsinstall.SHA256(strings.Repeat("b", 64)), Account: "operator", Port: 22, Service: windowsinstall.ServiceChange{PriorStatus: "Stopped", PriorStartType: "Manual", Start: true, SetAutomatic: true}, Rule: rule}, Problems: []windowsinstall.Problem{}}}
	call := func(args ...string) (int, string, string) {
		t.Helper()
		var out, stderr bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &stderr, Dependencies{SSHPreparer: preparer})
		return code, out.String(), stderr.String()
	}
	if code, _, stderr := call("setup", "ssh", "--platform", "linux", "--state-root", `C:\Box`, "--installation", "bbxi_"+strings.Repeat("a", 32)); code != 1 || !strings.Contains(stderr, "no host changes performed") || len(preparer.requests) != 0 {
		t.Fatalf("linux: %d %s", code, stderr)
	}
	if code, _, _ := call("setup", "ssh", "--platform", "windows", "--state-root", `C:\Box`, "--installation", "bbxi_"+strings.Repeat("a", 32), "--apply"); code != 2 || len(preparer.requests) != 0 {
		t.Fatalf("apply without plan: %d", code)
	}
	code, out, stderr := call("setup", "ssh", "--platform", "windows", "--state-root", `C:\Box`, "--installation", "bbxi_"+strings.Repeat("a", 32), "--remote-address", "100.64.0.0/10, fd7a:115c:a1e0::/48", "--firewall-profile", "Private")
	if code != 0 || !strings.Contains(out, "Plan SHA-256 "+strings.Repeat("b", 64)) || !strings.Contains(out, "Service sshd Stopped, start type Manual; start; set Automatic") || !strings.Contains(out, "Firewall rule "+rule.Name+": inbound TCP 22") || !strings.Contains(out, "Preview only") {
		t.Fatalf("preview: %d %s %s", code, out, stderr)
	}
	want := windowsinstall.SSHRequest{StateRoot: `C:\Box`, InstallationID: windowsinstall.InstallationID("bbxi_" + strings.Repeat("a", 32)), RemoteAddresses: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}, Profiles: []string{"Private"}}
	if got := preparer.requests[0]; got.StateRoot != want.StateRoot || got.InstallationID != want.InstallationID || strings.Join(got.RemoteAddresses, ",") != strings.Join(want.RemoteAddresses, ",") || strings.Join(got.Profiles, ",") != "Private" || got.Apply || got.Remove || got.ExpectedPlan != "" {
		t.Fatalf("request %+v", got)
	}
	preparer.result.State = "applied"
	code, out, stderr = call("setup", "ssh", "--platform", "windows", "--state-root", `C:\Box`, "--installation", "bbxi_"+strings.Repeat("a", 32), "--apply", "--expected-plan", strings.Repeat("b", 64), "--json")
	var result windowsinstall.SSHResult
	if err := json.Unmarshal([]byte(out), &result); code != 0 || err != nil || result.State != "applied" || !preparer.requests[1].Apply || preparer.requests[1].ExpectedPlan != windowsinstall.SHA256(strings.Repeat("b", 64)) {
		t.Fatalf("apply: %d %s %s", code, out, stderr)
	}
	if code, _, _ := call("setup", "ssh", "--platform", "windows", "--state-root", `C:\Box`, "--installation", "bbxi_"+strings.Repeat("a", 32), "--remove", "--apply"); code != 0 || !preparer.requests[2].Remove || !preparer.requests[2].Apply {
		t.Fatalf("remove: %d %+v", code, preparer.requests[2])
	}
}
