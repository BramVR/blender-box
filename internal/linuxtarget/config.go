package linuxtarget

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

const Distribution = "ubuntu-24.04-gnome-xorg"
const ProvenanceID = "blendersessiond-6d40e403-posix-9a54bfb9"

var absolutePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,220}$`)
var unitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.service$`)
var display = regexp.MustCompile(`^:[0-9]{1,2}$`)

type Desktop struct {
	Display    string `json:"display"`
	XAuthority string `json:"xauthority"`
}
type DaemonRuntime struct {
	VenvRoot         string `json:"venv_root"`
	PythonExecutable string `json:"python_executable"`
	ProvenanceID     string `json:"provenance_id"`
}
type Config struct {
	Distribution      string        `json:"distribution"`
	UID               uint32        `json:"uid"`
	Home              string        `json:"home"`
	WorkRoot          string        `json:"work_root"`
	HostExecutable    string        `json:"host_executable"`
	BlenderExecutable string        `json:"blender_executable"`
	UnitName          string        `json:"unit_name"`
	Desktop           Desktop       `json:"desktop"`
	Daemon            DaemonRuntime `json:"daemon"`
}

func ValidateAbsolutePath(value string) error {
	if !absolutePath.MatchString(value) || path.Clean(value) != value || strings.HasSuffix(value, "/") {
		return fmt.Errorf("unsafe absolute POSIX path %q", value)
	}
	for _, part := range strings.Split(value[1:], "/") {
		if part == "." || part == ".." || part == "" {
			return fmt.Errorf("unsafe POSIX path segment")
		}
	}
	return nil
}
func (value Desktop) Validate() error {
	if !display.MatchString(value.Display) {
		return fmt.Errorf("Linux desktop display must be a local X11 display such as :0")
	}
	return ValidateAbsolutePath(value.XAuthority)
}
func (value DaemonRuntime) Validate() error {
	if err := ValidateAbsolutePath(value.VenvRoot); err != nil {
		return err
	}
	if value.PythonExecutable != value.VenvRoot+"/bin/python3" {
		return fmt.Errorf("Linux daemon python_executable must be venv_root/bin/python3 in a copied CPython 3.12 venv")
	}
	if value.ProvenanceID != ProvenanceID {
		return fmt.Errorf("Linux daemon requires reviewed provenance %s; provision the corrected runtime externally", ProvenanceID)
	}
	return nil
}
func ValidateUID(uid uint32) error {
	if uid < 1000 || uid > 60000 {
		return fmt.Errorf("Linux desktop UID must be in 1000..60000")
	}
	return nil
}
func ValidateUnitName(name string) error {
	if !unitName.MatchString(name) {
		return fmt.Errorf("unsafe Linux unit_name")
	}
	return nil
}
func RuntimeDirectory(uid uint32) string { return fmt.Sprintf("/run/user/%d", uid) }
func DesktopEnvironment(uid uint32, desktop Desktop) map[string]string {
	return map[string]string{"DISPLAY": desktop.Display, "XAUTHORITY": desktop.XAuthority, "XDG_RUNTIME_DIR": RuntimeDirectory(uid), "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + RuntimeDirectory(uid) + "/bus"}
}
func (value Config) Validate() error {
	if value.Distribution != Distribution {
		return fmt.Errorf("Linux requires %s", Distribution)
	}
	if err := ValidateUID(value.UID); err != nil {
		return err
	}
	for _, name := range []string{value.Home, value.WorkRoot, value.HostExecutable, value.BlenderExecutable} {
		if err := ValidateAbsolutePath(name); err != nil {
			return err
		}
	}
	if value.WorkRoot == value.Home || strings.HasPrefix(value.Home, value.WorkRoot+"/") {
		return fmt.Errorf("Linux managed work_root must be separate from the home directory")
	}
	if value.Desktop.XAuthority == value.WorkRoot || strings.HasPrefix(value.Desktop.XAuthority, value.WorkRoot+"/") {
		return fmt.Errorf("Linux Xauthority must be outside managed work_root")
	}
	if !strings.HasPrefix(value.HostExecutable, value.WorkRoot+"/bin/") || path.Dir(value.HostExecutable) != value.WorkRoot+"/bin" {
		return fmt.Errorf("Linux host_executable must be directly inside work_root/bin")
	}
	if strings.HasPrefix(value.BlenderExecutable, value.WorkRoot+"/") {
		return fmt.Errorf("Linux Blender must be outside managed work_root")
	}
	if err := ValidateUnitName(value.UnitName); err != nil {
		return err
	}
	if err := value.Desktop.Validate(); err != nil {
		return err
	}
	if err := value.Daemon.Validate(); err != nil {
		return err
	}
	if strings.HasPrefix(value.Daemon.VenvRoot, value.WorkRoot+"/") || value.Daemon.VenvRoot == value.WorkRoot || strings.HasPrefix(value.WorkRoot, value.Daemon.VenvRoot+"/") {
		return fmt.Errorf("Linux daemon venv must be separate from managed work_root")
	}
	return nil
}
