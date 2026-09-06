package host

import "github.com/BramVR/blender-box/internal/orchestrator"

type Acknowledgement struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
}

type CapabilitiesRequest struct {
	UIActions               bool   `json:"ui_actions,omitempty"`
	BlenderExecutable       string `json:"blender_executable,omitempty"`
	SessionBrokerExecutable string `json:"session_broker_executable,omitempty"`
	SchemaVersion           int    `json:"schema_version"`
}

type CapabilitiesResponse struct {
	UIActions     *orchestrator.UIActionSupport `json:"ui_actions,omitempty"`
	SchemaVersion int                           `json:"schema_version"`
	Status        string                        `json:"status"`
	Captures      []orchestrator.CaptureSupport `json:"captures"`
}

type AcquireRequest struct {
	SchemaVersion int                    `json:"schema_version"`
	Claim         orchestrator.LockClaim `json:"claim"`
}

type StageRequest struct {
	SchemaVersion int                    `json:"schema_version"`
	Claim         orchestrator.LockClaim `json:"claim"`
	Files         []StageFile            `json:"files"`
}

type StageFile struct {
	Destination string `json:"destination"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Contents    []byte `json:"contents"`
}

type StatusRequest struct {
	SchemaVersion int                `json:"schema_version"`
	RunID         orchestrator.RunID `json:"run_id"`
}

type FetchRequest struct {
	SchemaVersion int                       `json:"schema_version"`
	Receipt       orchestrator.RunReceipt   `json:"receipt"`
	File          orchestrator.EvidenceFile `json:"file"`
}

type FetchResponse struct {
	SchemaVersion int    `json:"schema_version"`
	Contents      []byte `json:"contents"`
}

type SettleRequest struct {
	SchemaVersion           int                     `json:"schema_version"`
	Receipt                 orchestrator.RunReceipt `json:"receipt"`
	SessionBrokerExecutable string                  `json:"session_broker_executable"`
	SessionName             string                  `json:"session_name"`
}

type SettleResponse struct {
	SchemaVersion int                       `json:"schema_version"`
	Cleanup       orchestrator.CleanupState `json:"cleanup"`
}
