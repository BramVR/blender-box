package target

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

const MaxDocumentSize = 64 << 10

var sshAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type Target struct {
	platform string
	alias    string
	windows  windowstarget.Config
}

type document struct {
	SchemaVersion int                  `json:"schema_version"`
	Platform      string               `json:"platform"`
	SSHAlias      string               `json:"ssh_alias"`
	Windows       windowstarget.Config `json:"windows"`
}

func NewWindows(alias string, config windowstarget.Config) (Target, error) {
	value := Target{platform: "windows", alias: alias, windows: config}
	if err := value.Validate(); err != nil {
		return Target{}, err
	}
	return value, nil
}
func (value Target) Platform() string              { return value.platform }
func (value Target) SSHAlias() string              { return value.alias }
func (value Target) Windows() windowstarget.Config { return value.windows }
func (value Target) Validate() error {
	if value.platform != "windows" {
		return fmt.Errorf("target platform must be windows")
	}
	if !sshAliasPattern.MatchString(value.alias) {
		return fmt.Errorf("target ssh_alias is unsafe")
	}
	return value.windows.Validate()
}
func (value Target) MarshalJSON() ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(document{SchemaVersion: 2, Platform: value.platform, SSHAlias: value.alias, Windows: value.windows})
}
func (value Target) Fingerprint() string {
	encoded, _ := value.MarshalJSON()
	hash := sha256.Sum256(append([]byte("blender-box-target-v1\x00"), encoded...))
	return hex.EncodeToString(hash[:])
}
func Load(path string) (Target, error) {
	content, err := privatefile.ReadSource(path, MaxDocumentSize)
	if err != nil {
		return Target{}, fmt.Errorf("read target: %w", err)
	}
	return Decode(content)
}
func Decode(content []byte) (Target, error) {
	if len(content) > MaxDocumentSize {
		return Target{}, fmt.Errorf("target exceeds size limit")
	}
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(content, &fields); err != nil {
		return Target{}, fmt.Errorf("parse target: %w", err)
	}
	var version int
	if err := json.Unmarshal(fields["schema_version"], &version); err != nil {
		return Target{}, fmt.Errorf("invalid target schema_version")
	}
	switch version {
	case 1:
		var wire struct {
			SchemaVersion int    `json:"schema_version"`
			SSHAlias      string `json:"ssh_alias"`
			windowstarget.Config
		}
		if err := strictjson.Decode(content, &wire); err != nil {
			return Target{}, fmt.Errorf("parse target: %w", err)
		}
		return NewWindows(wire.SSHAlias, wire.Config)
	case 2:
		var wire document
		if err := strictjson.Decode(content, &wire); err != nil {
			return Target{}, fmt.Errorf("parse target: %w", err)
		}
		if wire.Platform != "windows" {
			return Target{}, fmt.Errorf("unsupported target platform")
		}
		return NewWindows(wire.SSHAlias, wire.Windows)
	default:
		return Target{}, fmt.Errorf("target schema_version must be 1 or 2")
	}
}
