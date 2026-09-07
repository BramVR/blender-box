package ssh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/target"
)

func pairedFixture(t *testing.T) (Runner, target.Connection) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("paired SSH requires POSIX credentials")
	}
	root := filepath.Join(t.TempDir(), "private")
	public, fingerprint, err := sshkey.Generate(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := target.PairedConnection(target.DirectSSH{Host: "host.invalid", Port: 2222, User: `DOMAIN\operator`, HostPublicKey: public, ClientPublicKeyHash: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	return Runner{ConfigRoot: root}, connection
}
func TestPairedConfigParsedByActualOpenSSH(t *testing.T) {
	runner, connection := pairedFixture(t)
	options, host, cleanup, err := runner.prepare(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	args := append(options, "-G", host)
	output, err := exec.Command("ssh", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh config parse: %v %s", err, output)
	}
	config := "\n" + string(output)
	for _, expected := range []string{"hostname host.invalid", "port 2222", `user DOMAIN\operator`, "hostkeyalias blender-box-pinned", "batchmode yes", "stricthostkeychecking true", "identitiesonly yes", "identityagent none", "certificatefile none", "globalknownhostsfile none", "controlmaster false", "forwardagent no", "clearallforwardings yes", "passwordauthentication no", "kbdinteractiveauthentication no", "hostbasedauthentication no", "gssapiauthentication no", "hostkeyalgorithms ssh-ed25519"} {
		if !strings.Contains(config, "\n"+expected+"\n") {
			t.Errorf("effective config missing %q", expected)
		}
	}
	if strings.Count(config, "\nidentityfile ") != 1 || strings.Count(config, "\nuserknownhostsfile ") != 1 {
		t.Fatal("ambient identities or known hosts remained")
	}
	if strings.Contains(config, "\ncontrolpath ") {
		t.Fatal("multiplexing path remained")
	}
	if strings.Contains(config, "\nproxycommand ") || strings.Contains(config, "\nproxyjump ") {
		t.Fatal("ambient proxy remained")
	}
}
func TestPairedSSHAndSCPUseSameHermeticPolicyAndRefuseChangedKey(t *testing.T) {
	runner, connection := pairedFixture(t)
	ctx := context.Background()
	directory := t.TempDir()
	record := filepath.Join(directory, "record")
	fake := `#!/bin/sh
printf '%s\n' "$0" "$@" >> "$SSH_TEST_RECORD"
if [ "$1" != '-F' ]; then exit 41; fi
cat "$2" >> "$SSH_TEST_RECORD"
cat >/dev/null
`
	for _, name := range []string{"ssh", "scp"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(fake), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SSH_TEST_RECORD", record)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_AUTH_SOCK", "untrusted-agent")
	if _, err := runner.Run(ctx, connection, []string{"host-command"}, []byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := runner.Upload(ctx, connection, "/tmp/source", `C:\Box\payload.bin`); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"HostName \"host.invalid\"", "Port 2222", "IdentityAgent none", "StrictHostKeyChecking yes", "PreferredAuthentications publickey", "ControlPath none", "ProxyCommand none"} {
		if strings.Count(string(data), expected) != 2 {
			t.Errorf("SSH/SCP policy did not both contain %q", expected)
		}
	}
	before := string(data)
	direct, _ := connection.Direct()
	path := filepath.Join(runner.ConfigRoot, "credentials", direct.ClientPublicKeyHash, "id_ed25519")
	otherRoot := filepath.Join(t.TempDir(), "replacement")
	_, otherHash, err := sshkey.Generate(ctx, otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := sshkey.Read(ctx, otherRoot, otherHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, connection, []string{"must-not-run"}, nil); err == nil {
		t.Fatal("changed key accepted")
	}
	if err := runner.Upload(ctx, connection, "/tmp/source", `C:\Box\payload.bin`); err == nil {
		t.Fatal("SCP accepted changed key")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, connection, []string{"must-not-run"}, nil); err == nil {
		t.Fatal("missing key accepted")
	}
	after, _ := os.ReadFile(record)
	if string(after) != before {
		t.Fatal("credential refusal happened after transport process start")
	}
}
