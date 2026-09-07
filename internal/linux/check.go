package linux

import (
	"context"
	"fmt"
	"time"

	"github.com/BramVR/blender-box/internal/linuxruntime"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/target"
)

type SSH = sshtransport.CommandRunner
type CheckResult = linuxruntime.CheckResult

func Check(ctx context.Context, ssh SSH, selected target.Target) (CheckResult, error) {
	if err := selected.Validate(); err != nil {
		return CheckResult{}, err
	}
	if selected.Platform() != "linux" {
		return CheckResult{}, fmt.Errorf("Linux command requires linux platform")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var result CheckResult
	if err := NewAdapter(ssh).invokeJSON(ctx, selected, "linux-check", selected.Linux(), &result); err != nil {
		return CheckResult{}, fmt.Errorf("inspect Linux host: %w; run linux setup after externally provisioning prerequisites", err)
	}
	required := map[string]bool{"host.linux": false, "host.desktop": false, "daemon.runtime": false, "host.unit": false, "work-root.access": false, "blender.executable": false}
	failed := false
	for _, check := range result.Checks {
		seen, ok := required[check.ID]
		if !ok || seen || !check.Required {
			return CheckResult{}, fmt.Errorf("Linux check returned invalid checks")
		}
		required[check.ID] = true
		if !check.Passed {
			failed = true
		}
	}
	for _, seen := range required {
		if !seen {
			return CheckResult{}, fmt.Errorf("Linux check omitted a required check")
		}
	}
	if result.SchemaVersion != 1 || (result.Status != "pass" && result.Status != "fail") || failed != (result.Status == "fail") || (result.Status == "pass" && result.BlenderVersion != "5.2.0") {
		return CheckResult{}, fmt.Errorf("Linux check returned invalid contract")
	}
	return result, nil
}
