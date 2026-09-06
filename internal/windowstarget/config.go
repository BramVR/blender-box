package windowstarget

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
)

const (
	maxWindowsPathTail         = 238
	maxSetupWorkRootTail       = maxWindowsPathTail - len(`\.setup-`) - 32 - len(`.ps1`)
	maxSetupHostExecutableTail = maxWindowsPathTail - len(`.setup-backup-`) - 32
)

var (
	taskNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$`)
	userPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\\@-]{0,127}$`)
	workRootPattern = regexp.MustCompile(`^[A-Za-z]:\\[^\r\n"'*?<>|]{1,238}$`)
	scpPathPattern  = regexp.MustCompile(`^[A-Za-z]:\\[A-Za-z0-9._\\-]{1,238}$`)
	reservedDevice  = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$`)
)

type Config struct {
	SSHUser                 string `json:"ssh_user"`
	InteractiveUser         string `json:"interactive_user"`
	WorkRoot                string `json:"work_root"`
	TaskName                string `json:"task_name"`
	BlenderExecutable       string `json:"blender_executable"`
	SessionBrokerExecutable string `json:"session_broker_executable"`
	HostExecutable          string `json:"host_executable"`
}

func (value Config) Validate() error {
	if !userPattern.MatchString(value.SSHUser) {
		return fmt.Errorf("target ssh_user is unsafe")
	}
	if !ValidateWindowsPath(value.WorkRoot) {
		return fmt.Errorf("target work_root must be an absolute safe Windows path")
	}
	if !ValidateLegacySCPWindowsPath(value.WorkRoot) {
		return fmt.Errorf("target work_root must use the legacy-SCP-safe Windows path grammar")
	}
	if len(value.WorkRoot[3:]) > maxSetupWorkRootTail {
		return fmt.Errorf("target work_root must reserve space for setup staging paths")
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
		if !ValidateWindowsPath(path) {
			return fmt.Errorf("target %s must be an absolute safe Windows file path", label)
		}
	}
	if windowsPathTailUnits(value.HostExecutable) > maxSetupHostExecutableTail {
		return fmt.Errorf("target host_executable must reserve space for setup replacement paths")
	}
	for label, path := range map[string]string{
		"session_broker_executable": value.SessionBrokerExecutable,
		"host_executable":           value.HostExecutable,
	} {
		rootKey := strings.ToUpper(value.WorkRoot)
		if !strings.HasPrefix(strings.ToUpper(path), rootKey+`\`) {
			return fmt.Errorf("target %s must be inside work_root", label)
		}
		parent := path[:strings.LastIndex(path, `\`)]
		if strings.ToUpper(parent) == rootKey {
			return fmt.Errorf("target %s must be inside a dedicated executable directory", label)
		}
		pathKey := strings.ToUpper(path)
		if strings.HasPrefix(pathKey, strings.ToUpper(value.WorkRoot+`\runs\`)) || strings.HasPrefix(pathKey, strings.ToUpper(value.WorkRoot+`\receipts\`)) {
			return fmt.Errorf("target %s must not use a reserved state directory", label)
		}
	}
	executables := []string{value.BlenderExecutable, value.SessionBrokerExecutable, value.HostExecutable}
	seenExecutables := make(map[string]struct{}, len(executables))
	for _, path := range executables {
		key := strings.ToUpper(path)
		if _, exists := seenExecutables[key]; exists {
			return fmt.Errorf("target executable paths must be distinct")
		}
		seenExecutables[key] = struct{}{}
	}
	return nil
}

// ValidateLegacySCPWindowsPath accepts paths that cannot add syntax to a legacy remote SCP command.
func ValidateLegacySCPWindowsPath(path string) bool {
	return scpPathPattern.MatchString(path) && ValidateWindowsPath(path)
}

// ValidateWindowsPath accepts the absolute, non-device Windows path grammar used across process boundaries.
func ValidateWindowsPath(path string) bool {
	if !workRootPattern.MatchString(path) || windowsPathTailUnits(path) > maxWindowsPathTail || strings.Contains(path, "/") || strings.HasSuffix(path, `\`) {
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

func windowsPathTailUnits(path string) int {
	if len(path) < 3 {
		return 0
	}
	return len(utf16.Encode([]rune(path[3:])))
}
