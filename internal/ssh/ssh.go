package ssh

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

const (
	maxStdoutBytes = 24 << 20
	maxStderrBytes = 64 << 10
)

type CommandRunner interface {
	Run(context.Context, target.Connection, []string, []byte) ([]byte, error)
}
type Transport interface {
	CommandRunner
	Upload(context.Context, target.Connection, string, string) error
}
type Runner struct{ ConfigRoot string }

func (runner Runner) Run(ctx context.Context, connection target.Connection, remoteArgs []string, stdin []byte) ([]byte, error) {
	if _, paired := connection.Direct(); paired {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
	}
	options, host, cleanup, err := runner.prepare(ctx, connection)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	arguments := []string{
		"-o", "RequestTTY=no",
		"-o", "RemoteCommand=none",
		"--",
		host,
	}
	arguments = append(arguments, remoteArgs...)
	arguments = append(options, arguments...)
	command := exec.CommandContext(ctx, "ssh", arguments...)
	command.WaitDelay = time.Second
	command.Stdin = bytes.NewReader(stdin)
	stdout := newBoundedBuffer(maxStdoutBytes)
	stderr := newBoundedBuffer(maxStderrBytes)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if stdout.exceeded || stderr.exceeded {
			return nil, fmt.Errorf("SSH output exceeded its limit")
		}
		if message := stderr.String(); message != "" {
			return nil, fmt.Errorf("SSH failed: %s", message)
		}
		return nil, fmt.Errorf("SSH failed: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("SSH output exceeded its limit")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func (runner Runner) Upload(ctx context.Context, connection target.Connection, source, destination string) error {
	if _, paired := connection.Direct(); paired {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
	}
	options, host, cleanup, err := runner.prepare(ctx, connection)
	if err != nil {
		return err
	}
	defer cleanup()
	arguments, err := uploadArguments(host, source, destination)
	if err != nil {
		return err
	}
	arguments = append(options, arguments...)
	command := exec.CommandContext(ctx, "scp", arguments...)
	command.WaitDelay = time.Second
	stdout := newBoundedBuffer(maxStdoutBytes)
	stderr := newBoundedBuffer(maxStderrBytes)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if stdout.exceeded || stderr.exceeded {
			return fmt.Errorf("SCP output exceeded its limit")
		}
		if message := stderr.String(); message != "" {
			return fmt.Errorf("SCP failed: %s", message)
		}
		return fmt.Errorf("SCP failed: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return fmt.Errorf("SCP output exceeded its limit")
	}
	return nil
}

func uploadArguments(host, source, destination string) ([]string, error) {
	if !windowstarget.ValidateLegacySCPWindowsPath(destination) {
		return nil, fmt.Errorf("SCP destination uses unsafe remote-shell syntax")
	}
	return []string{"-q", "--", source, host + ":" + strings.ReplaceAll(destination, `\`, "/")}, nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (buffer *boundedBuffer) Write(content []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return len(content), nil
	}
	if len(content) > remaining {
		_, _ = buffer.buffer.Write(content[:remaining])
		buffer.exceeded = true
		return len(content), nil
	}
	return buffer.buffer.Write(content)
}

func (buffer *boundedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func (buffer *boundedBuffer) String() string {
	return buffer.buffer.String()
}

func (runner Runner) prepare(ctx context.Context, connection target.Connection) ([]string, string, func(), error) {
	noop := func() {}
	if err := connection.Validate(); err != nil {
		return nil, "", noop, err
	}
	direct, paired := connection.Direct()
	if !paired {
		return nil, connection.Alias(), noop, nil
	}
	root := runner.ConfigRoot
	if root == "" {
		var err error
		root, err = target.ConfigDir()
		if err != nil {
			return nil, "", noop, err
		}
	}
	key, err := sshkey.Read(ctx, root, direct.ClientPublicKeyHash)
	if err != nil {
		return nil, "", noop, fmt.Errorf("paired SSH credential: %w", err)
	}
	directory, err := os.MkdirTemp("", "blender-box-ssh-")
	if err != nil {
		return nil, "", noop, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	keyPath := filepath.Join(directory, "identity")
	hostsPath := filepath.Join(directory, "known_hosts")
	configPath := filepath.Join(directory, "config")
	quote := func(value string) string {
		return "\"" + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + "\""
	}
	config := "Host *\n" +
		" HostName " + quote(direct.Host) + "\n Port " + strconv.Itoa(int(direct.Port)) + "\n User " + quote(direct.User) + "\n" +
		" IdentityFile " + quote(keyPath) + "\n UserKnownHostsFile " + quote(hostsPath) + "\n" +
		" HostKeyAlias blender-box-pinned\n HostKeyAlgorithms ssh-ed25519\n GlobalKnownHostsFile none\n StrictHostKeyChecking yes\n VerifyHostKeyDNS no\n UpdateHostKeys no\n" +
		" BatchMode yes\n PreferredAuthentications publickey\n PubkeyAuthentication yes\n IdentitiesOnly yes\n IdentityAgent none\n CertificateFile none\n PKCS11Provider none\n PasswordAuthentication no\n KbdInteractiveAuthentication no\n HostbasedAuthentication no\n GSSAPIAuthentication no\n" +
		" ControlMaster no\n ControlPath none\n ControlPersist no\n ForwardAgent no\n ForwardX11 no\n ClearAllForwardings yes\n Tunnel no\n ProxyCommand none\n ProxyJump none\n CanonicalizeHostname no\n PermitLocalCommand no\n RequestTTY no\n RemoteCommand none\n ConnectTimeout 30\n ConnectionAttempts 1\n"
	for path, contents := range map[string][]byte{keyPath: key, hostsPath: []byte("blender-box-pinned " + direct.HostPublicKey + "\n"), configPath: []byte(config)} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			cleanup()
			return nil, "", noop, err
		}
	}
	return []string{"-F", configPath}, "blender-box-pinned", cleanup, nil
}
