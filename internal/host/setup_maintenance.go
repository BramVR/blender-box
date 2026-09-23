package host

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"encoding/json"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
)

// SetupClaim fences maintenance independently of Run and Session authority.
type SetupClaim struct {
	SchemaVersion  int       `json:"schema_version"`
	InstallationID string    `json:"installation_id"`
	OperationID    string    `json:"operation_id"`
	ExecutionToken string    `json:"execution_token"`
	RequestSHA256  string    `json:"request_sha256"`
	RootIdentity   string    `json:"root_identity"`
	OwnerSID       string    `json:"owner_sid"`
	Deadline       time.Time `json:"deadline"`
}

func (c SetupClaim) Validate() error {
	for pattern, value := range map[string]string{`^bbxi_[a-f0-9]{32}$`: c.InstallationID, `^bbxo_[a-f0-9]{32}$`: c.OperationID, `^bbxe_[a-f0-9]{32}$`: c.ExecutionToken, `^[a-f0-9]{64}$`: c.RequestSHA256} {
		if !regexp.MustCompile(pattern).MatchString(value) {
			return fmt.Errorf("invalid pending setup identity")
		}
	}
	if c.SchemaVersion != 1 || c.RootIdentity == "" || c.OwnerSID == "" || c.Deadline.IsZero() {
		return fmt.Errorf("invalid pending setup claim")
	}
	return nil
}

func ReadSetupClaim(root string) (SetupClaim, error) {
	var claim SetupClaim
	if _, err := os.Lstat(filepath.Join(root, "pending-setup.json")); err != nil {
		return claim, err
	}
	data, err := readRegularFile(filepath.Join(root, "pending-setup.json"), 16<<10)
	if err != nil {
		return claim, err
	}
	if err = strictjson.Decode(data, &claim); err != nil {
		return claim, err
	}
	return claim, claim.Validate()
}

// RejectPendingSetup rejects even malformed or dangling authority records.
func RejectPendingSetup(root string) error {
	if _, err := os.Lstat(filepath.Join(root, "pending-setup.json")); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("active or unresolved setup execution")
}

func inspectSetupClaim(root string, own *SetupClaim) error {
	if own == nil {
		return RejectPendingSetup(root)
	}
	if err := own.Validate(); err != nil {
		return err
	}
	current, err := ReadSetupClaim(root)
	if err != nil {
		return err
	}
	if current != *own {
		return fmt.Errorf("pending setup execution changed")
	}
	return nil
}

// PublishSetupClaim and ClearSetupClaim require the shared maintenance locks.
func PublishSetupClaim(root string, claim SetupClaim) error {
	if err := claim.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(claim)
	if err != nil {
		return err
	}
	return privatefile.Publish(root, "pending-setup.json", data, false)
}
func ClearSetupClaim(root string, claim SetupClaim) error {
	if err := inspectSetupClaim(root, &claim); err != nil {
		return err
	}
	return os.Remove(filepath.Join(root, "pending-setup.json"))
}
