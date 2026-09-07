package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/BramVR/blender-box/internal/windowsinstall"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSetupSSHPreviewHelp(t *testing.T) {
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"setup", "ssh", "--help"}, strings.NewReader(""), &out, &stderr, Dependencies{})
	if code != 0 || !strings.Contains(out.String()+stderr.String(), "request") {
		t.Fatalf("SSH preview help: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
}

func TestSetupSSHActualCLIRefusals(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "blender-box")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "../../cmd/blender-box")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, output)
	}
	stateRoot := filepath.Join(root, "absent-host-state")
	request := windowsinstall.SSHPreparationRequest{SchemaVersion: 1, Platform: "windows", InstallationID: "bbxi_11111111111111111111111111111111", OperationID: "bbxo_22222222222222222222222222222222", StateRoot: `/fixture/absent-host-state`, Account: "fixture", ControlAccounts: []string{"control"}, Deadline: time.Now().UTC().Add(4 * time.Minute), Connection: windowsinstall.SSHConnectionScope{Hostname: "fixture.example", Port: 22, LoginUser: "fixture", LocalAddresses: []string{"192.0.2.10"}, RemotePrefixes: []string{"198.51.100.0/24"}, FirewallProfiles: []string{"private"}}}
	invalidRoot, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	request.StateRoot = `C:\fixture\absent-host-state`
	valid, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		data    []byte
		apply   bool
		problem string
	}{
		{name: "malformed", data: []byte(`{"schema_version":`)},
		{name: "duplicate", data: []byte(`{"schema_version":1,"schema_version":1}`)},
		{name: "oversized", data: bytes.Repeat([]byte(" "), (64<<10)+1)},
		{name: "apply-before-request-read", apply: true},
		{name: "invalid-posix-root", data: invalidRoot, problem: "invalid-request"},
		{name: "native-posix-refusal", data: valid, problem: "unsupported-platform"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.problem == "unsupported-platform" && runtime.GOOS == "windows" {
				t.Skip("POSIX refusal only; no native host access")
			}
			path := filepath.Join(root, tc.name+".json")
			if tc.data != nil {
				if err := os.WriteFile(path, tc.data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"setup", "ssh", "--request", path, "--json"}
			if tc.apply {
				args = append(args, "--apply")
			}
			command := exec.Command(binary, args...)
			command.Env = append(os.Environ(), "BLENDER_BOX_CONFIG_DIR="+filepath.Join(root, "absent-client-state"))
			var out, stderr bytes.Buffer
			command.Stdout, command.Stderr = &out, &stderr
			err := command.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("exit: %v stdout=%s stderr=%s", err, &out, &stderr)
			}
			if tc.problem == "" && out.Len() != 0 {
				t.Fatalf("invalid request produced plan: %s", &out)
			}
			if tc.apply && !strings.Contains(stderr.String(), "apply is unsupported") {
				t.Fatalf("apply inspected request first: %s", &stderr)
			}
			if tc.problem != "" {
				var result windowsinstall.SSHPreparationPreviewResult
				if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.State != "refused" || result.Plan != nil || len(result.Problems) != 1 || result.Problems[0].Code != tc.problem {
					t.Fatalf("refusal: %s %v", &out, err)
				}
			}
			for _, path := range []string{stateRoot, filepath.Join(root, "absent-client-state")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("refusal created state %s: %v", path, err)
				}
			}
			if tc.data != nil {
				current, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(current, tc.data) {
					t.Fatal("request changed")
				}
			}
		})
	}
}
