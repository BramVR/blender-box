package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/BramVR/blender-box/internal/target"
	"io"
	"os"
)

const maxHostBinary = 64 << 20

type SetupResult struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Applied       bool   `json:"applied"`
	HostSize      int64  `json:"host_size"`
	HostSHA256    string `json:"host_sha256"`
}

func Setup(_ context.Context, _ SetupSSH, selected target.Target, source string, apply bool) (SetupResult, error) {
	if err := selected.Validate(); err != nil {
		return SetupResult{}, err
	}
	contents, err := readHostBinary(source)
	if err != nil {
		return SetupResult{}, err
	}
	hash := sha256.Sum256(contents)
	result := SetupResult{SchemaVersion: 1, Status: "plan", HostSize: int64(len(contents)), HostSHA256: hex.EncodeToString(hash[:])}
	if apply {
		return result, fmt.Errorf("legacy-setup-unowned: legacy setup cannot establish installation ownership; use host-local setup install with a runtime manifest")
	}
	return result, nil
}
func readHostBinary(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("host binary must be a regular file without symlinks")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxHostBinary+1))
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 {
		return nil, fmt.Errorf("host binary must not be empty")
	}
	if len(contents) > maxHostBinary || int64(len(contents)) != info.Size() {
		return nil, fmt.Errorf("host binary exceeds its limit or changed during read")
	}
	return contents, nil
}
