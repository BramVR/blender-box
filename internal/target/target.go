package target

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	sshAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	taskNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$`)
	userPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\\@-]{0,127}$`)
	workRootPattern = regexp.MustCompile(`^[A-Za-z]:\\[^\r\n"'*?<>|]{1,238}$`)
)

// Target contains operator-selected host values. It contains no credentials or addresses.
type Target struct {
	SchemaVersion   int    `json:"schema_version"`
	SSHAlias        string `json:"ssh_alias"`
	WorkRoot        string `json:"work_root"`
	InteractiveUser string `json:"interactive_user"`
	TaskName        string `json:"task_name"`
}

func Load(path string) (Target, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Target{}, fmt.Errorf("read target: %w", err)
	}
	var value Target
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
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
	if !workRootPattern.MatchString(value.WorkRoot) || hasTraversal(value.WorkRoot) {
		return fmt.Errorf("target work_root must be an absolute safe Windows path")
	}
	if !userPattern.MatchString(value.InteractiveUser) {
		return fmt.Errorf("target interactive_user is unsafe")
	}
	if !taskNamePattern.MatchString(value.TaskName) {
		return fmt.Errorf("target task_name is unsafe")
	}
	return nil
}

func hasTraversal(path string) bool {
	for _, segment := range strings.Split(strings.ReplaceAll(path, "/", `\`), `\`) {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}
