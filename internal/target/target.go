package target

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

var (
	sshAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	taskNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$`)
	userPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\\@-]{0,127}$`)
	workRootPattern = regexp.MustCompile(`^[A-Za-z]:\\[^\r\n"'*?<>|]{1,238}$`)
	reservedDevice  = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$`)
)

// Target contains operator-selected host values. It contains no credentials or addresses.
type Target struct {
	SchemaVersion           int    `json:"schema_version"`
	SSHAlias                string `json:"ssh_alias"`
	WorkRoot                string `json:"work_root"`
	InteractiveUser         string `json:"interactive_user"`
	TaskName                string `json:"task_name"`
	BlenderExecutable       string `json:"blender_executable"`
	SessionBrokerExecutable string `json:"session_broker_executable"`
	HostExecutable          string `json:"host_executable"`
}

func Load(path string) (Target, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Target{}, fmt.Errorf("read target: %w", err)
	}
	var value Target
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Target{}, fmt.Errorf("parse target: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return Target{}, fmt.Errorf("parse target: trailing JSON value")
		}
		return Target{}, fmt.Errorf("parse target: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Target{}, err
	}
	return value, nil
}

func (value Target) Validate() error {
	if value.SchemaVersion != 1 {
		return fmt.Errorf("target schema_version must be 1")
	}
	if !sshAliasPattern.MatchString(value.SSHAlias) {
		return fmt.Errorf("target ssh_alias is unsafe")
	}
	if !isCanonicalWindowsPath(value.WorkRoot) {
		return fmt.Errorf("target work_root must be an absolute safe Windows path")
	}
	if !userPattern.MatchString(value.InteractiveUser) {
		return fmt.Errorf("target interactive_user is unsafe")
	}
	if !taskNamePattern.MatchString(value.TaskName) {
		return fmt.Errorf("target task_name is unsafe")
	}
	for label, path := range map[string]string{
		"blender_executable":        value.BlenderExecutable,
		"session_broker_executable": value.SessionBrokerExecutable,
		"host_executable":           value.HostExecutable,
	} {
		if !isCanonicalWindowsPath(path) {
			return fmt.Errorf("target %s must be an absolute safe Windows file path", label)
		}
	}
	return nil
}

func isCanonicalWindowsPath(path string) bool {
	if !workRootPattern.MatchString(path) || strings.Contains(path, "/") || strings.HasSuffix(path, `\`) {
		return false
	}
	for _, segment := range strings.Split(path[3:], `\`) {
		if segment == "" || segment == "." || segment == ".." || strings.TrimRight(segment, " .") != segment {
			return false
		}
		for _, character := range segment {
			if character < 32 || strings.ContainsRune(`%:"'*?<>|`, character) {
				return false
			}
		}
		base := segment
		if dot := strings.IndexByte(base, '.'); dot >= 0 {
			base = base[:dot]
		}
		if reservedDevice.MatchString(base) {
			return false
		}
	}
	return true
}
