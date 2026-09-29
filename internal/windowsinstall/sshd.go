package windowsinstall

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// sshdFacts is one elevated observation of the host's OpenSSH server for a given account and
// client address. Pairing and setup ssh both decide from it and never edit sshd_config.
type sshdFacts struct {
	ServiceStatus        string
	StartType            string
	Port                 uint16
	PubkeyAuthentication bool
	AuthorizedKeysFile   string // absolute, resolved for the account
	HostKeyEd25519       string // canonical "ssh-ed25519 <b64>", comment stripped
	Elevated             bool
}
type sshdResolver interface {
	facts(ctx context.Context, account, host, addr string) (sshdFacts, error)
}

// sshdConfig is what `sshd -T -C user=..,host=..,addr=..` says before path expansion.
type sshdConfig struct {
	Port                 uint16
	PubkeyAuthentication bool
	AuthorizedKeysFile   string // first entry, raw
	HostKey              string // the ed25519 host key path, raw
}

func parseSSHDT(output string) (sshdConfig, error) {
	var config sshdConfig
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "port":
			port, err := strconv.ParseUint(fields[1], 10, 16)
			if err != nil || port == 0 {
				return sshdConfig{}, fmt.Errorf("sshd -T reported an invalid port")
			}
			if config.Port == 0 {
				config.Port = uint16(port)
			}
		case "pubkeyauthentication":
			config.PubkeyAuthentication = strings.EqualFold(fields[1], "yes")
		case "authorizedkeysfile":
			if config.AuthorizedKeysFile == "" {
				config.AuthorizedKeysFile = fields[1]
			}
		case "hostkey":
			if strings.HasSuffix(strings.ToLower(fields[1]), "ssh_host_ed25519_key") {
				config.HostKey = fields[1]
			}
		}
	}
	if config.Port == 0 || config.AuthorizedKeysFile == "" || config.HostKey == "" {
		return sshdConfig{}, fmt.Errorf("sshd -T output lacks port, authorizedkeysfile or an ed25519 hostkey")
	}
	return config, nil
}

// expandAuthorizedKeys applies OpenSSH's AuthorizedKeysFile tokens the way Windows sshd does:
// __PROGRAMDATA__, %u, %h, %% and a relative path below the account's profile.
func expandAuthorizedKeys(raw, user, home, programData string) (string, error) {
	if raw == "" || strings.EqualFold(raw, "none") {
		return "", fmt.Errorf("sshd resolves no authorized keys file for this account")
	}
	if strings.ContainsAny(raw, "\r\n\"*?<>|") {
		return "", fmt.Errorf("unsafe authorized keys path")
	}
	var expanded strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			expanded.WriteByte(raw[i])
			continue
		}
		if i+1 >= len(raw) {
			return "", fmt.Errorf("unterminated token in authorized keys path")
		}
		i++
		switch raw[i] {
		case '%':
			expanded.WriteByte('%')
		case 'u':
			expanded.WriteString(user)
		case 'h':
			expanded.WriteString(home)
		default:
			return "", fmt.Errorf("unsupported token %%%c in authorized keys path", raw[i])
		}
	}
	path := strings.ReplaceAll(strings.ReplaceAll(expanded.String(), "__PROGRAMDATA__", programData), "/", `\`)
	if !windowsRooted(path) {
		path = strings.TrimRight(home, `\`) + `\` + path
	}
	if !windowsRooted(path) || strings.Contains(path, `\..\`) || strings.HasSuffix(path, `\..`) {
		return "", fmt.Errorf("authorized keys path must be absolute")
	}
	return path, nil
}

func windowsRooted(path string) bool {
	return len(path) >= 3 && path[1] == ':' && path[2] == '\\' && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z')
}
