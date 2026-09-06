package target

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/BramVR/blender-box/internal/linuxtarget"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

const MaxDocumentSize = 64 << 10

var sshAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type Target struct {
	connection Connection
	platform   string
	alias      string
	windows    windowstarget.Config
	linux      linuxtarget.Config
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
func NewLinux(alias string, config linuxtarget.Config) (Target, error) {
	value := Target{platform: "linux", alias: alias, linux: config}
	if err := value.Validate(); err != nil {
		return Target{}, err
	}
	return value, nil
}
func (value Target) Linux() linuxtarget.Config     { return value.linux }
func (value Target) Platform() string              { return value.platform }
func (value Target) SSHAlias() string              { return value.alias }
func (value Target) Windows() windowstarget.Config { return value.windows }
func (value Target) Validate() error {
	if value.platform != "windows" && value.platform != "linux" {
		return fmt.Errorf("target platform must be windows or linux")
	}
	if err := value.Connection().Validate(); err != nil {
		return err
	}
	if value.platform == "linux" {
		return value.linux.Validate()
	}
	return value.windows.Validate()
}
func (value Target) MarshalJSON() ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	if direct, paired := value.Connection().Direct(); paired {
		if value.platform == "linux" {
			return json.Marshal(struct {
				SchemaVersion int                `json:"schema_version"`
				Platform      string             `json:"platform"`
				SSH           DirectSSH          `json:"ssh"`
				Linux         linuxtarget.Config `json:"linux"`
			}{3, "linux", direct, value.linux})
		}
		return json.Marshal(struct {
			SchemaVersion int                  `json:"schema_version"`
			Platform      string               `json:"platform"`
			SSH           DirectSSH            `json:"ssh"`
			Windows       windowstarget.Config `json:"windows"`
		}{3, "windows", direct, value.windows})
	}
	if value.platform == "linux" {
		return json.Marshal(struct {
			SchemaVersion int                `json:"schema_version"`
			Platform      string             `json:"platform"`
			SSHAlias      string             `json:"ssh_alias"`
			Linux         linuxtarget.Config `json:"linux"`
		}{2, "linux", value.alias, value.linux})
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
		var platform string
		if err := json.Unmarshal(fields["platform"], &platform); err != nil {
			return Target{}, fmt.Errorf("invalid target platform")
		}
		if platform == "linux" {
			var wire struct {
				SchemaVersion int                `json:"schema_version"`
				Platform      string             `json:"platform"`
				SSHAlias      string             `json:"ssh_alias"`
				Linux         linuxtarget.Config `json:"linux"`
			}
			if err := strictjson.Decode(content, &wire); err != nil {
				return Target{}, fmt.Errorf("parse target: %w", err)
			}
			return NewLinux(wire.SSHAlias, wire.Linux)
		}
		var wire document
		if err := strictjson.Decode(content, &wire); err != nil {
			return Target{}, fmt.Errorf("parse target: %w", err)
		}
		if wire.Platform != "windows" {
			return Target{}, fmt.Errorf("unsupported target platform")
		}
		return NewWindows(wire.SSHAlias, wire.Windows)
	case 3:
		var platform string
		if err := json.Unmarshal(fields["platform"], &platform); err != nil {
			return Target{}, fmt.Errorf("invalid target platform")
		}
		if platform == "linux" {
			var wire struct {
				SchemaVersion int                `json:"schema_version"`
				Platform      string             `json:"platform"`
				SSH           DirectSSH          `json:"ssh"`
				Linux         linuxtarget.Config `json:"linux"`
			}
			if err := strictjson.Decode(content, &wire); err != nil {
				return Target{}, err
			}
			return NewPaired(Target{platform: "linux", linux: wire.Linux}, wire.SSH)
		}
		var wire struct {
			SchemaVersion int                  `json:"schema_version"`
			Platform      string               `json:"platform"`
			SSH           DirectSSH            `json:"ssh"`
			Windows       windowstarget.Config `json:"windows"`
		}
		if err := strictjson.Decode(content, &wire); err != nil {
			return Target{}, err
		}
		return NewPaired(Target{platform: wire.Platform, windows: wire.Windows}, wire.SSH)
	default:
		return Target{}, fmt.Errorf("target schema_version must be 1, 2 or 3")
	}
}

func (value *Target) UnmarshalJSON(data []byte) error {
	decoded, err := Decode(data)
	if err != nil {
		return err
	}
	*value = decoded
	return nil
}
