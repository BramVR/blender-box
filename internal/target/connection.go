package target

import (
	"fmt"
	"net"
	"regexp"

	"github.com/BramVR/blender-box/internal/sshkey"
)

// Connection carries either an operator alias or the complete paired authority.
type Connection struct {
	alias  string
	direct *DirectSSH
}
type DirectSSH struct {
	Host                string `json:"host"`
	Port                uint16 `json:"port"`
	User                string `json:"user"`
	HostPublicKey       string `json:"host_public_key"`
	ClientPublicKeyHash string `json:"client_public_key_hash"`
}

var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
var userPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\\-]{0,127}$`)
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func AliasConnection(alias string) (Connection, error) {
	c := Connection{alias: alias}
	return c, c.Validate()
}
func PairedConnection(direct DirectSSH) (Connection, error) {
	c := Connection{direct: &direct}
	return c, c.Validate()
}
func (c Connection) Alias() string { return c.alias }
func (c Connection) Direct() (DirectSSH, bool) {
	if c.direct == nil {
		return DirectSSH{}, false
	}
	return *c.direct, true
}
func (c Connection) Validate() error {
	if c.direct == nil {
		if !sshAliasPattern.MatchString(c.alias) {
			return fmt.Errorf("target ssh_alias is unsafe")
		}
		return nil
	}
	if c.alias != "" {
		return fmt.Errorf("paired connection cannot contain an SSH alias")
	}
	d := c.direct
	if (!hostnamePattern.MatchString(d.Host) && net.ParseIP(d.Host) == nil) || d.Port == 0 || !userPattern.MatchString(d.User) {
		return fmt.Errorf("invalid paired SSH endpoint")
	}
	if canonical, err := sshkey.CanonicalPublicKey(d.HostPublicKey); err != nil || canonical != d.HostPublicKey {
		return fmt.Errorf("paired SSH requires a canonical Ed25519 host public key")
	}
	if !fingerprintPattern.MatchString(d.ClientPublicKeyHash) {
		return fmt.Errorf("invalid paired client public-key fingerprint")
	}
	return nil
}
func NewPaired(installed Target, direct DirectSSH) (Target, error) {
	connection, err := PairedConnection(direct)
	if err != nil {
		return Target{}, err
	}
	installed.alias = ""
	installed.connection = connection
	if err := installed.Validate(); err != nil {
		return Target{}, err
	}
	return installed, nil
}
func (value Target) Connection() Connection {
	if value.connection.direct != nil {
		return value.connection
	}
	return Connection{alias: value.alias}
}
