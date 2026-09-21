package linuxruntime

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/linuxtarget"
)

type CheckEvidence struct {
	ID       string `json:"id"`
	Passed   bool   `json:"passed"`
	Required bool   `json:"required"`
	Message  string `json:"message,omitempty"`
}
type CheckResult struct {
	SchemaVersion  int             `json:"schema_version"`
	Status         string          `json:"status"`
	Checks         []CheckEvidence `json:"checks"`
	BlenderVersion string          `json:"blender_version,omitempty"`
}

func Check(ctx context.Context, config linuxtarget.Config) CheckResult {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	result := CheckResult{SchemaVersion: 1, Status: "pass", Checks: []CheckEvidence{}}
	add := func(id string, err error) {
		check := CheckEvidence{ID: id, Passed: err == nil, Required: true}
		if err != nil {
			result.Status = "fail"
			check.Message = err.Error()
		}
		result.Checks = append(result.Checks, check)
	}
	platformErr := config.Validate()
	if platformErr == nil {
		platformErr = CheckPlatform(ctx, config.UID, config.Home)
	}
	add("host.linux", platformErr)
	if platformErr != nil {
		for _, id := range []string{"host.desktop", "daemon.runtime", "host.unit", "work-root.access", "blender.executable"} {
			add(id, fmt.Errorf("requires supported Linux host configuration"))
		}
		return result
	}
	add("host.desktop", CheckDesktop(ctx, config.UID, config.Desktop))
	_, daemonErr := Run(ctx, config.Daemon, []string{"capabilities", "--require", "blender-box-v1", "--require-capability", "typed-call-error-reason"}, nil)
	add("daemon.runtime", daemonErr)
	unitState, unitErr := CheckUnit(ctx, config.WorkRoot, config.HostExecutable, config.Home, config.UnitName, config.UID, config.Desktop)
	if unitErr == nil && unitState != "inactive" {
		unitErr = UnitUnavailable(unitState)
	}
	add("host.unit", unitErr)
	add("work-root.access", checkState(config))
	blenderErr := CheckExecutable(config.BlenderExecutable, config.UID)
	if blenderErr == nil {
		output, err := execute(ctx, config.BlenderExecutable, []string{"--version"}, CleanEnvironment(nil))
		blenderErr = err
		if err == nil {
			first, _, _ := strings.Cut(string(output), "\n")
			if first != "Blender 5.2.0" {
				blenderErr = fmt.Errorf("supported Blender version is 5.2.0")
			} else {
				result.BlenderVersion = "5.2.0"
			}
		}
	}
	add("blender.executable", blenderErr)
	return result
}
func CheckExecutable(name string, uid uint32) error {
	if err := SafePath(name, uid, false); err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("expected executable regular file %s", name)
	}
	return nil
}
func checkState(config linuxtarget.Config) error {
	if err := SafePath(config.WorkRoot, config.UID, true); err != nil {
		return err
	}
	if err := CheckExecutable(config.HostExecutable, config.UID); err != nil {
		return err
	}
	for _, lock := range []string{".operation.lock", ".launch.lock"} {
		if err := SafePath(config.WorkRoot+"/"+lock, config.UID, true); err != nil {
			return err
		}
		info, err := os.Lstat(config.WorkRoot + "/" + lock)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("host process locks must be private regular files")
		}
	}
	for _, name := range []string{"runs", "receipts"} {
		count := 0
		err := walkBounded(config.WorkRoot+"/"+name, 10000, func(path string, entry os.DirEntry) error {
			count++
			if count > 10000 {
				return fmt.Errorf("state tree inspection exceeds entry bound")
			}
			return SafePath(path, config.UID, false)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
