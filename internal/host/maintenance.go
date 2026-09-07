package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BramVR/blender-box/internal/orchestrator"
)

// WithMaintenance holds the same authority locks as Run acquisition and startup.
func WithMaintenance(ctx context.Context, root string, action func() error) error {
	return WithSetupMaintenance(ctx, root, nil, action)
}

// WithSetupMaintenance admits only the exact pending setup worker.
func WithSetupMaintenance(ctx context.Context, root string, own *SetupClaim, action func() error) error {
	if err := validateRoot(root); err != nil {
		return err
	}
	for _, name := range []string{".operation.lock", ".launch.lock"} {
		if info, err := os.Lstat(filepath.Join(root, name)); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				return fmt.Errorf("invalid maintenance lock")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	release, err := acquireOperation(ctx, root)
	if err != nil {
		return err
	}
	defer release()
	releaseLaunch, acquired, err := tryAcquireLaunch(root)
	if err != nil {
		return err
	}
	if !acquired {
		return fmt.Errorf("launch-in-progress")
	}
	defer releaseLaunch()
	if err := InspectSetupMaintenance(root, own); err != nil {
		return err
	}
	return action()
}

// InspectMaintenance reads authority without creating lock files or directories.
func InspectMaintenance(root string) error {
	return InspectSetupMaintenance(root, nil)
}

func InspectSetupMaintenance(root string, own *SetupClaim) error {
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return nil
	}
	if err := validateRoot(root); err != nil {
		return err
	}
	if err := inspectSetupClaim(root, own); err != nil {
		return err
	}
	for _, name := range []string{"host-lock.json", "pending-request.json"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			return fmt.Errorf("active or unresolved host authority: %s", name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, directory := range []string{"runs", "receipts"} {
		path := filepath.Join(root, directory)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("invalid %s authority directory", directory)
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) > 4096 {
			return fmt.Errorf("excessive retained Run authority")
		}
		if directory == "runs" {
			if len(entries) != 0 {
				return fmt.Errorf("active or unresolved Run root")
			}
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				return fmt.Errorf("unknown Run receipt")
			}
			data, err := readRegularFile(filepath.Join(path, entry.Name()), maxScenarioJSON)
			if err != nil {
				return err
			}
			if err := scanMaintenanceJSON(json.NewDecoder(bytes.NewReader(data))); err != nil {
				return fmt.Errorf("ambiguous Run receipt: %w", err)
			}
			var receipt orchestrator.RunReceipt
			if err := decodeJSONBytes(data, &receipt, maxScenarioJSON); err != nil {
				return fmt.Errorf("corrupt Run receipt: %w", err)
			}
			if receipt.SchemaVersion != 1 || receipt.Claim.Validate() != nil || entry.Name() != string(receipt.Claim.RunID)+".json" || !receipt.Cleanup.Known() || !terminalMaintenanceState(receipt.State) {
				return fmt.Errorf("unresolved Run receipt")
			}
			if receipt.SessionID != "" && receipt.SessionID.Validate() != nil {
				return fmt.Errorf("invalid Session identity")
			}
		}
	}
	return nil
}

func terminalMaintenanceState(state orchestrator.RunState) bool {
	switch state {
	case orchestrator.StateComplete, orchestrator.StateFailed, orchestrator.StateTimedOut, orchestrator.StateCleanupFailed:
		return true
	}
	return false
}

func scanMaintenanceJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	keys := map[string]bool{}
	for decoder.More() {
		if delimiter == '{' {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || keys[key] {
				return fmt.Errorf("duplicate JSON key")
			}
			keys[key] = true
		}
		if err := scanMaintenanceJSON(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
