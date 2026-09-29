package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/BramVR/blender-box/internal/target"
)

func TestClassifyOpenSSHStderr(t *testing.T) {
	changedKey := "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
		"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n" +
		"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
		"Host key for blender-box-pinned has changed and you have requested strict checking.\n" +
		"Host key verification failed.\n"
	for _, test := range []struct {
		name, stderr, host string
		exit               int
		class              FailureClass
		detail             string
	}{
		{"refused", "ssh: connect to host 192.0.2.10 port 22: Connection refused\r\n", "192.0.2.10", 255, HostUnreachable, "ssh: connect to host 192.0.2.10 port 22: Connection refused"},
		{"linux timeout", "ssh: connect to host box.example port 22: Connection timed out\n", "box.example", 255, HostUnreachable, "ssh: connect to host box.example port 22: Connection timed out"},
		{"macOS timeout on tailnet address", "ssh: connect to host 100.101.102.103 port 22: Operation timed out\n", "100.101.102.103", 255, TailscaleUnreachable, "ssh: connect to host 100.101.102.103 port 22: Operation timed out"},
		{"no route on tailnet IPv6", "ssh: connect to host fd7a:115c:a1e0::1 port 22: No route to host\n", "fd7a:115c:a1e0::1", 255, TailscaleUnreachable, "ssh: connect to host fd7a:115c:a1e0::1 port 22: No route to host"},
		{"MagicDNS name unresolved", "ssh: Could not resolve hostname studio.tail1234.ts.net: nodename nor servname provided, or not known\n", "studio.tail1234.ts.net", 255, TailscaleUnreachable, "ssh: Could not resolve hostname studio.tail1234.ts.net: nodename nor servname provided, or not known"},
		{"address outside CGNAT range", "ssh: connect to host 100.128.0.1 port 22: No route to host\n", "100.128.0.1", 255, HostUnreachable, "ssh: connect to host 100.128.0.1 port 22: No route to host"},
		{"banner timeout", "Connection timed out during banner exchange\nConnection to 192.0.2.10 port 22 timed out\n", "192.0.2.10", 255, HostUnreachable, "Connection timed out during banner exchange"},
		{"changed pinned key on tailnet", changedKey, "100.101.102.103", 255, HostKeyMismatch, "Host key verification failed."},
		{"unknown pinned key", "No ED25519 host key is known for blender-box-pinned and you have requested strict checking.\nHost key verification failed.\n", "192.0.2.10", 255, HostKeyMismatch, "Host key verification failed."},
		{"revoked key", "operator@192.0.2.10: Permission denied (publickey,keyboard-interactive).\r\n", "192.0.2.10", 255, AuthRejected, "operator@192.0.2.10: Permission denied (publickey,keyboard-interactive)."},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := classify(test.exit, test.stderr, test.host)
			if failure == nil || failure.Class != test.class || failure.Detail != test.detail {
				t.Fatalf("classify = %+v, want %s %q", failure, test.class, test.detail)
			}
		})
	}
	for name, test := range map[string]struct {
		exit   int
		stderr string
	}{
		"remote command failure":  {1, "operator@192.0.2.10: Permission denied (publickey).\n"},
		"unrecognised ssh output": {255, "kex_exchange_identification: read: Connection reset by peer\n"},
	} {
		if failure := classify(test.exit, test.stderr, "192.0.2.10"); failure != nil {
			t.Fatalf("%s classified as %+v", name, failure)
		}
	}
}

func TestFailureErrorLeadsWithClassAndNextStep(t *testing.T) {
	failure := &Failure{Class: TailscaleUnreachable, Detail: "ssh: connect to host 100.101.102.103 port 22: Operation timed out"}
	want := "tailscale-unreachable: connect this machine to the tailnet (`tailscale status`) and check that the host is online there. ssh: connect to host 100.101.102.103 port 22: Operation timed out"
	if failure.Error() != want {
		t.Fatalf("Error() = %q", failure.Error())
	}
}

func TestRunnerReturnsClassifiedFailuresAndKeepsRemoteErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake OpenSSH executables are POSIX shell scripts")
	}
	directory := t.TempDir()
	fake := "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$FAKE_SSH_STDERR\" >&2\nexit \"$FAKE_SSH_EXIT\"\n"
	for _, name := range []string{"ssh", "scp"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(fake), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	connection, err := target.AliasConnection("studio.tail1234.ts.net")
	if err != nil {
		t.Fatal(err)
	}
	runner := Runner{}
	ctx := context.Background()

	t.Setenv("FAKE_SSH_EXIT", "255")
	t.Setenv("FAKE_SSH_STDERR", "ssh: connect to host studio.tail1234.ts.net port 22: Connection refused")
	_, runErr := runner.Run(ctx, connection, []string{"exit"}, nil)
	uploadErr := runner.Upload(ctx, connection, "/tmp/source", `C:\Box\payload.bin`)
	for name, err := range map[string]error{"run": runErr, "upload": uploadErr} {
		var failure *Failure
		if !errors.As(err, &failure) || failure.Class != TailscaleUnreachable {
			t.Fatalf("%s error = %v", name, err)
		}
	}

	t.Setenv("FAKE_SSH_EXIT", "3")
	t.Setenv("FAKE_SSH_STDERR", "host command failed")
	_, err = runner.Run(ctx, connection, []string{"exit"}, nil)
	var failure *Failure
	if errors.As(err, &failure) || err == nil || err.Error() != "SSH failed: host command failed\n" {
		t.Fatalf("remote failure = %v", err)
	}
}
