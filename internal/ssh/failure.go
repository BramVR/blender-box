package ssh

import (
	"fmt"
	"net/netip"
	"strings"
)

// FailureClass names an OpenSSH connection failure a user can act on.
type FailureClass string

const (
	HostUnreachable      FailureClass = "host-unreachable"
	TailscaleUnreachable FailureClass = "tailscale-unreachable"
	HostKeyMismatch      FailureClass = "host-key-mismatch"
	AuthRejected         FailureClass = "auth-rejected"
)

var nextSteps = map[FailureClass]string{
	HostUnreachable:      "check that the host is on, sshd is running, and this machine can reach its address and port",
	TailscaleUnreachable: "connect this machine to the tailnet (`tailscale status`) and check that the host is online there",
	HostKeyMismatch:      "the host identity differs from the pinned key; do not replace trust; verify the host on its console and pair again from a new offer",
	AuthRejected:         "the host refused this client key; check the pairing on the host with `pair status --state-root`, or pair again",
}

// Failure is an SSH or SCP error that OpenSSH itself reported before any remote command ran.
type Failure struct {
	Class  FailureClass
	Detail string
}

func (failure *Failure) Next() string { return nextSteps[failure.Class] }

func (failure *Failure) Error() string {
	if failure.Detail == "" {
		return fmt.Sprintf("%s: %s", failure.Class, failure.Next())
	}
	return fmt.Sprintf("%s: %s. %s", failure.Class, failure.Next(), failure.Detail)
}

var stderrPatterns = []struct {
	fragment string
	class    FailureClass
}{
	// Host key checks run before authentication, so they win over later lines.
	{"host key verification failed", HostKeyMismatch},
	{"remote host identification has changed", HostKeyMismatch},
	{"permission denied (publickey", AuthRejected},
	{"connection refused", HostUnreachable},
	{"timed out", HostUnreachable},
	{"no route to host", HostUnreachable},
	{"network is unreachable", HostUnreachable},
	{"could not resolve hostname", HostUnreachable},
}

// classify only reads exit status 255, which OpenSSH reserves for its own errors;
// any other status came from the remote command and keeps its original message.
func classify(exit int, stderr, host string) *Failure {
	if exit != 255 {
		return nil
	}
	lines := strings.Split(stderr, "\n")
	for _, pattern := range stderrPatterns {
		for _, line := range lines {
			if !strings.Contains(strings.ToLower(line), pattern.fragment) {
				continue
			}
			class := pattern.class
			if class == HostUnreachable && tailscaleAddress(host) {
				class = TailscaleUnreachable
			}
			return &Failure{Class: class, Detail: strings.TrimSpace(line)}
		}
	}
	return nil
}

var tailscalePrefixes = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

func tailscaleAddress(host string) bool {
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		for _, prefix := range tailscalePrefixes {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSuffix(host, ".")), ".ts.net")
}
