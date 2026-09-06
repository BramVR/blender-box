package windows

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/target"
)

type checkSSH struct {
	output         string
	deadlineWindow time.Duration
}

func (fake *checkSSH) Run(ctx context.Context, _ string, _ []string, _ []byte) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	if ok {
		fake.deadlineWindow = time.Until(deadline)
	}
	return []byte(fake.output), nil
}

func TestCheckRejectsMalformedOrContradictoryEvidence(t *testing.T) {
	validChecks := `[
{"id":"host.windows","passed":true,"required":true},
{"id":"host.console-user","passed":true,"required":true},
{"id":"host.ssh-user","passed":true,"required":true},
{"id":"host.limited-token-policy","passed":true,"required":true},
{"id":"blender.executable","passed":true,"required":true},
{"id":"daemon.executable","passed":true,"required":true},
{"id":"host.executable","passed":true,"required":true},
{"id":"work-root.access","passed":true,"required":true},
{"id":"work-root.state-tree","passed":true,"required":true},
{"id":"task.interactive","passed":true,"required":true}
]`
	cases := map[string]string{
		"null":                `{"schema_version":1,"status":"pass","checks":null}`,
		"empty array":         `{"schema_version":1,"status":"pass","checks":[]}`,
		"object":              `{"schema_version":1,"status":"pass","checks":{}}`,
		"missing required ID": `{"schema_version":1,"status":"pass","checks":[{"id":"host.windows","passed":true,"required":true}]}`,
		"duplicate ID":        `{"schema_version":1,"status":"pass","checks":[{"id":"host.windows","passed":true,"required":true},{"id":"host.windows","passed":true,"required":true}]}`,
		"pass with failed check": `{"schema_version":1,"status":"pass","checks":[
{"id":"host.windows","passed":false,"required":true},
{"id":"host.console-user","passed":true,"required":true},
{"id":"host.ssh-user","passed":true,"required":true},
{"id":"host.limited-token-policy","passed":true,"required":true},
{"id":"blender.executable","passed":true,"required":true},
{"id":"daemon.executable","passed":true,"required":true},
{"id":"host.executable","passed":true,"required":true},
{"id":"work-root.access","passed":true,"required":true},
{"id":"work-root.state-tree","passed":true,"required":true},
{"id":"task.interactive","passed":true,"required":true}]}`,
		"fail without failure": `{"schema_version":1,"status":"fail","checks":` + validChecks + `}`,
	}

	for name, output := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Check(context.Background(), &checkSSH{output: output}, target.Target{})
			if err == nil || !strings.Contains(err.Error(), "invalid contract") {
				t.Fatalf("Check() error = %v, want invalid contract", err)
			}
		})
	}
}

func TestCheckAcceptsCompleteFailedEvidence(t *testing.T) {
	output := `{"schema_version":1,"status":"fail","checks":[
{"id":"host.windows","passed":true,"required":true},
{"id":"host.console-user","passed":true,"required":true},
{"id":"host.ssh-user","passed":true,"required":true},
{"id":"host.limited-token-policy","passed":true,"required":true},
{"id":"blender.executable","passed":false,"required":true},
{"id":"daemon.executable","passed":false,"required":true},
{"id":"host.executable","passed":false,"required":true},
{"id":"work-root.access","passed":false,"required":true},
{"id":"work-root.state-tree","passed":false,"required":true},
{"id":"task.interactive","passed":false,"required":true}]}`

	fake := &checkSSH{output: output}
	result, err := Check(context.Background(), fake, target.Target{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "fail" || len(result.Checks) != 10 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if fake.deadlineWindow < 90*time.Second || fake.deadlineWindow > 2*time.Minute {
		t.Fatalf("Windows check deadline window = %s, want a bounded cold-start budget", fake.deadlineWindow)
	}
}

func TestCheckStateTreeAcceptsControllerOwnedInheritedRuntimeState(t *testing.T) {
	if !strings.Contains(checkScript, "[bool]$AllowControllerOwner") ||
		!strings.Contains(checkScript, "if ($AllowControllerOwner) { $trustedOwners += $ControllerSid }") ||
		!strings.Contains(checkScript, "$modify $false $true $true $true") ||
		!strings.Contains(checkScript, "Test-ConservativePathAccess $directory.FullName $ControllerSid $fullControl $isRoot") ||
		!strings.Contains(checkScript, "Test-ConservativePathAccess $child.FullName $ControllerSid $fullControl $false") {
		t.Fatal("state-tree inspection does not accept runtime state owned by the declared controller with inherited task access")
	}
}

func TestCheckRequiresProvisionedStateDirectories(t *testing.T) {
	if !strings.Contains(checkScript, "if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }") {
		t.Fatal("state-tree inspection accepts an absent state directory")
	}
	if !strings.Contains(checkScript, "[System.IO.Path]::Combine([string]$config.work_root, 'setup-owner')") || !strings.Contains(checkScript, "Existing Run, receipt, and setup-owner trees") {
		t.Fatal("state-tree inspection omits the setup-owner authority root")
	}
}

func TestCheckAncestorsTrustOnlyControllerAndSystemAuthority(t *testing.T) {
	if !strings.Contains(checkScript, "function Test-TrustedAncestor([string]$Path, [string]$ControllerSid)") ||
		!strings.Contains(checkScript, "$trustedWriters = @(\n        'S-1-5-18'") ||
		strings.Contains(checkScript, "$trustedWriters = @(\n        $PrincipalSid,") {
		t.Fatal("inspection trusts the interactive task user to replace a managed-path ancestor")
	}
}

func TestCheckRequiresSSHControllerAndInteractiveTaskToShareSID(t *testing.T) {
	if !strings.Contains(checkScript, "$sshSid -eq $expectedSSHSid -and $sshSid -eq $expectedSid") ||
		!strings.Contains(checkScript, "Slice 0 requires the SSH controller and interactive task to use the same Windows identity") {
		t.Fatal("inspection accepts separate controller and interactive task identities")
	}
}

func TestCheckRequiresRegularSealedOperationAndLaunchLocks(t *testing.T) {
	for _, required := range []string{
		"$operationPath = [System.IO.Path]::Combine([string]$config.work_root, '.operation.lock')",
		"$launchPath = [System.IO.Path]::Combine([string]$config.work_root, '.launch.lock')",
		"Test-Path -LiteralPath $operationPath -PathType Leaf",
		"Test-Path -LiteralPath $launchPath -PathType Leaf",
		"Test-SafePath $operationPath $expectedSid $sshSid $fullControl $true $true $false $true",
		"Test-SafePath $launchPath $expectedSid $sshSid $fullControl $true $true $false $true",
	} {
		if !strings.Contains(checkScript, required) {
			t.Fatalf("inspection does not seal both host lock files: missing %q", required)
		}
	}
}

func TestCheckRequiresBlenderBoxSessionBrokerContract(t *testing.T) {
	for _, required := range []string{
		"function Test-SessionBrokerContract",
		"function Invoke-SessionBrokerProbe",
		"'capabilities', '--require', 'blender-box-v1', '--require-capability', 'typed-call-error-reason', '--require-capability', 'windows-setup-owner-v1'",
		"Start-Process -FilePath $Path",
		"-RedirectStandardOutput 'NUL'",
		"-RedirectStandardError '\\\\.\\NUL'",
		"$null = $process.Handle",
		"WaitForExit(10000)",
		"$daemonContractOK = $daemonSafe -and (Test-SessionBrokerContract $daemonPath)",
		"$daemonOK -and $daemonContractOK",
	} {
		if !strings.Contains(checkScript, required) {
			t.Fatalf("inspection does not enforce daemon contract: missing %q", required)
		}
	}
	for _, forbidden := range []string{"$process.WaitForExit()", ".GetAwaiter().GetResult()", "ReadToEndAsync", "CopyToAsync", "MemoryStream"} {
		if strings.Contains(checkScript, forbidden) {
			t.Fatalf("inspection contains unbounded daemon probe operation %q", forbidden)
		}
	}
}

func TestCheckRequiresDeclaredControllerTaskManagementAuthority(t *testing.T) {
	if !strings.Contains(checkScript, "$controllerCanManage") ||
		!strings.Contains(checkScript, "($aceMask -band $genericAll) -eq $genericAll") ||
		!strings.Contains(checkScript, "return $controllerCanExecute -and $controllerCanManage") {
		t.Fatal("task inspection does not require controller update and launch authority")
	}
}

func TestCheckAcceptsCanonicalizedTaskFullControl(t *testing.T) {
	for _, required := range []string{
		"$taskFullControl = 0x001F01FF",
		"($aceMask -band $taskFullControl) -eq $taskFullControl",
	} {
		if !strings.Contains(checkScript, required) {
			t.Fatalf("task inspection does not accept canonicalized FullControl: missing %q", required)
		}
	}
}

func TestCheckRequiresControllerMutationAndTaskRootFileInheritance(t *testing.T) {
	for _, required := range []string{
		"function Test-RootStateFileInheritance",
		"$objectInheritance",
		"$inheritOnly",
		"Test-ConservativePathAccess $directory.FullName $ControllerSid $fullControl $isRoot",
		"Test-ConservativePathAccess $child.FullName $ControllerSid $fullControl $false",
		"Test-ConservativePathAccess ([System.IO.Path]::GetDirectoryName($daemonPath)) $sshSid $fullControl $true",
		"Test-ConservativePathAccess ([System.IO.Path]::GetDirectoryName($hostPath)) $sshSid $fullControl $true",
		"Test-ConservativePathAccess ([string]$config.work_root) $sshSid $fullControl $true",
		"Test-RootStateFileInheritance ([string]$config.work_root) $expectedSid $sshSid",
	} {
		if !strings.Contains(checkScript, required) {
			t.Fatalf("Windows check missing %q", required)
		}
	}
}
