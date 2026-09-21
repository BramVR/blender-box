package linux

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BramVR/blender-box/internal/linuxruntime"
	"github.com/BramVR/blender-box/internal/linuxtarget"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/target"
)

//go:embed setup.py
var setupScript string

type SetupResult struct {
	SchemaVersion   int      `json:"schema_version"`
	Status          string   `json:"status"`
	Applied         bool     `json:"applied"`
	HostSize        int64    `json:"host_size"`
	HostSHA256      string   `json:"host_sha256"`
	HostDestination string   `json:"host_destination"`
	UnitName        string   `json:"unit_name"`
	UnitBytes       string   `json:"unit_bytes"`
	UnitSHA256      string   `json:"unit_sha256"`
	UnitDestination string   `json:"unit_destination"`
	Prerequisites   []string `json:"prerequisites"`
}

func Setup(ctx context.Context, ssh SSH, selected target.Target, source string, apply bool) (SetupResult, error) {
	if err := selected.Validate(); err != nil {
		return SetupResult{}, err
	}
	if selected.Platform() != "linux" {
		return SetupResult{}, fmt.Errorf("Linux command requires linux platform")
	}
	contents, err := privatefile.ReadSource(source, 64<<20)
	if err != nil {
		return SetupResult{}, fmt.Errorf("read Linux host binary: %w", err)
	}
	if len(contents) == 0 {
		return SetupResult{}, fmt.Errorf("Linux host binary is empty")
	}
	config := selected.Linux()
	unit := linuxruntime.UnitBytes(config.WorkRoot, config.HostExecutable, config.Home, config.UID, config.Desktop)
	hash := sha256.Sum256(contents)
	unitHash := sha256.Sum256([]byte(unit))
	result := SetupResult{SchemaVersion: 1, Status: "plan", HostSize: int64(len(contents)), HostSHA256: hex.EncodeToString(hash[:]), HostDestination: config.HostExecutable, UnitName: config.UnitName, UnitBytes: unit, UnitSHA256: hex.EncodeToString(unitHash[:]), UnitDestination: linuxruntime.UnitPath(config.Home, config.UnitName), Prerequisites: []string{
		"Unverified: Ubuntu 24.04, systemd 255 and one active local GNOME Xorg desktop owned by the declared SSH UID.",
		"Unverified: externally provisioned sealed copied CPython 3.12 venv with reviewed daemon provenance " + linuxtarget.ProvenanceID + "; the current wheel is unsupported.",
		"Unverified: trusted Blender 5.2.0 executable, private physical paths and inactive static user unit without a Host Lock.",
	}}
	if !apply {
		return result, nil
	}
	if ssh == nil {
		return SetupResult{}, fmt.Errorf("SSH transport is unavailable")
	}
	input, err := json.Marshal(struct {
		Config linuxtarget.Config `json:"config"`
		Plan   SetupResult        `json:"plan"`
		Binary []byte             `json:"binary"`
	}{config, result, contents})
	if err != nil {
		return SetupResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	output, err := ssh.Run(ctx, selected.SSHAlias(), []string{"/usr/bin/python3 -I -S -B -c " + Quote(setupScript)}, input)
	if err != nil {
		return SetupResult{}, fmt.Errorf("Linux setup apply: %w", err)
	}
	var receipt struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		HostSHA256    string `json:"host_sha256"`
		UnitSHA256    string `json:"unit_sha256"`
	}
	if err := strictjson.Decode(output, &receipt); err != nil {
		return SetupResult{}, fmt.Errorf("Linux setup receipt: %w", err)
	}
	if receipt.SchemaVersion != 1 || receipt.Status != "applied" || receipt.HostSHA256 != result.HostSHA256 || receipt.UnitSHA256 != result.UnitSHA256 {
		return SetupResult{}, fmt.Errorf("Linux setup returned mismatched publication receipt")
	}
	result.Status = "applied"
	result.Applied = true
	return result, nil
}
