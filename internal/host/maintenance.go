package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/BramVR/blender-box/internal/strictjson"
	"io"
	"io/fs"
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

// MaintenanceReader supplies bounded read-only observations to maintenance policy.
type MaintenanceReader interface {
	Stat(string) (fs.FileInfo, error)
	ReadDir(string, int) ([]fs.DirEntry, error)
	ReadFile(string, int) ([]byte, error)
}

type maintenanceFiles struct{}

func (maintenanceFiles) Stat(path string) (fs.FileInfo, error) {
	return os.Lstat(path)
}
func (maintenanceFiles) ReadDir(path string, maximum int) ([]fs.DirEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(maximum + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return entries, nil
}
func (maintenanceFiles) ReadFile(path string, maximum int) ([]byte, error) {
	return readRegularFile(path, int64(maximum))
}
func InspectSetupMaintenance(root string, own *SetupClaim) error {
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return nil
	}
	if err := validateRoot(root); err != nil {
		return err
	}
	return InspectSetupMaintenanceWithReader(root, own, maintenanceFiles{})
}

// InspectSetupMaintenanceWithReader applies the same authority policy through reader.
func InspectSetupMaintenanceWithReader(root string, own *SetupClaim, reader MaintenanceReader) error {
	info, err := reader.Stat(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !filepath.IsAbs(root) || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("state root must be an existing regular directory")
	}
	if err := inspectMaintenanceSetupClaim(root, own, reader); err != nil {
		return err
	}
	for _, name := range []string{"host-lock.json", "pending-request.json"} {
		if _, err := reader.Stat(filepath.Join(root, name)); err == nil {
			return fmt.Errorf("active or unresolved host authority: %s", name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, directory := range []string{"runs", "receipts"} {
		path := filepath.Join(root, directory)
		info, err := reader.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("invalid %s authority directory", directory)
		}
		entries, err := reader.ReadDir(path, 4096)
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
			data, err := reader.ReadFile(filepath.Join(path, entry.Name()), maxScenarioJSON)
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

func inspectMaintenanceSetupClaim(root string, own *SetupClaim, reader MaintenanceReader) error {
	path := filepath.Join(root, "pending-setup.json")
	if own == nil {
		if _, err := reader.Stat(path); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		return fmt.Errorf("active or unresolved setup execution")
	}
	if err := own.Validate(); err != nil {
		return err
	}
	current, err := readMaintenanceSetupClaim(root, reader)
	if err != nil {
		return err
	}
	if current != *own {
		return fmt.Errorf("pending setup execution changed")
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

func readMaintenanceSetupClaim(root string, reader MaintenanceReader) (SetupClaim, error) {
	var claim SetupClaim
	path := filepath.Join(root, "pending-setup.json")
	if _, err := reader.Stat(path); err != nil {
		return claim, err
	}
	data, err := reader.ReadFile(path, 16<<10)
	if err != nil {
		return claim, err
	}
	if err := strictjson.Decode(data, &claim); err != nil {
		return claim, err
	}
	return claim, claim.Validate()
}
