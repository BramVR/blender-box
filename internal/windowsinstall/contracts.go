package windowsinstall

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/target"
)

type InstallationID string
type OperationID string
type SHA256 string
type ArtifactRole string

const (
	ArtifactHostExecutable ArtifactRole = "host-executable"
	ArtifactDaemonLauncher ArtifactRole = "daemon-launcher"
	ArtifactDaemonWheel    ArtifactRole = "daemon-wheel"
)

type SourceProvenance struct {
	Repository        string `json:"repository"`
	SourceCommit      string `json:"source_commit"`
	PatchSHA256       SHA256 `json:"patch_sha256"`
	BuildRecipeSHA256 SHA256 `json:"build_recipe_sha256"`
}
type Artifact struct {
	Role       ArtifactRole     `json:"role"`
	Name       string           `json:"name"`
	Size       int64            `json:"size"`
	SHA256     SHA256           `json:"sha256"`
	Provenance SourceProvenance `json:"provenance"`
}
type RuntimeManifest struct {
	SchemaVersion      int        `json:"schema_version"`
	Platform           string     `json:"platform"`
	Architecture       string     `json:"architecture"`
	Artifacts          []Artifact `json:"artifacts"`
	PythonRequires     string     `json:"python_requires"`
	DaemonProtocol     string     `json:"daemon_protocol"`
	DaemonCapabilities []string   `json:"daemon_capabilities"`
}
type Publication struct {
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
	Name   string `json:"name,omitempty"`
	Error  string `json:"error,omitempty"`
}
type Request struct {
	Operation      string         `json:"operation"`
	Platform       string         `json:"platform"`
	StateRoot      string         `json:"state_root"`
	InstallationID InstallationID `json:"installation_id"`
	OperationID    OperationID    `json:"operation_id"`
	RuntimePath    string         `json:"runtime_path"`
	BlenderPath    string         `json:"blender_path"`
	PythonPath     string         `json:"python_path"`
	SSHAlias       string         `json:"ssh_alias"`
	WindowsUser    string         `json:"windows_user"`
	TaskName       string         `json:"task_name"`
	ExpectedPlan   SHA256         `json:"expected_plan"`
	Apply          bool           `json:"apply"`
	TargetOut      string         `json:"target_out"`
	SaveTarget     string         `json:"save_target"`
	ExecutionToken string         `json:"execution_token"`
}

type File struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Size     int64  `json:"size"`
	SHA256   SHA256 `json:"sha256,omitempty"`
	Identity string `json:"identity,omitempty"`
}
type Candidate struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	SHA256   SHA256 `json:"sha256"`
	Identity string `json:"identity"`
}
type PythonPrerequisite struct {
	Candidate  Candidate `json:"candidate"`
	Home       string    `json:"home"`
	Template   Candidate `json:"template"`
	DLL        Candidate `json:"dll"`
	VenvSource Candidate `json:"venv_source"`
}
type Inspection struct {
	OwnerSID          string              `json:"owner_sid"`
	RootIdentity      string              `json:"root_identity"`
	BlenderCandidates []Candidate         `json:"blender_candidates"`
	Python            *PythonPrerequisite `json:"python,omitempty"`
}
type Plan struct {
	PlanSHA256     SHA256 `json:"plan_sha256"`
	ManifestSHA256 SHA256 `json:"manifest_sha256,omitempty"`
	Files          []File `json:"files"`
}
type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Result struct {
	Execution         *Execution     `json:"execution,omitempty"`
	TargetPublication Publication    `json:"target_publication"`
	SchemaVersion     int            `json:"schema_version"`
	OperationID       OperationID    `json:"operation_id,omitempty"`
	InstallationID    InstallationID `json:"installation_id,omitempty"`
	State             string         `json:"state"`
	Completion        string         `json:"completion"`
	Plan              Plan           `json:"plan"`
	Inspection        Inspection     `json:"inspection"`
	Files             []File         `json:"files"`
	Retained          []string       `json:"retained"`
	Target            *target.Target `json:"target,omitempty"`
	Problems          []Problem      `json:"problems"`
}
type Executor interface {
	Execute(context.Context, Request) (Result, error)
}

var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var installID = regexp.MustCompile(`^bbxi_[a-f0-9]{32}$`)
var operationID = regexp.MustCompile(`^bbxo_[a-f0-9]{32}$`)

func newID(prefix string) (string, error) {
	var bytes [16]byte
	_, err := rand.Read(bytes[:])
	return prefix + hex.EncodeToString(bytes[:]), err
}
func digest(bytes []byte) SHA256 {
	sum := sha256.Sum256(bytes)
	return SHA256(hex.EncodeToString(sum[:]))
}
func objectDigest(value any) SHA256 {
	bytes, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return digest(bytes)
}
func problem(result Result, code string, err error) (Result, error) {
	if errors.Is(err, errNativeCleanupUnknown) {
		result.Completion = "unknown"
	}
	if result.State == "" || result.State == "planned" {
		result.State = "conflict"
	}
	result.Problems = append(result.Problems, Problem{code, err.Error()})
	return result, fmt.Errorf("%s: %w", code, err)
}

// UnmarshalJSON keeps the target's validated document boundary when results cross a process.
func (result *Result) UnmarshalJSON(data []byte) error {
	type fields Result
	var decoded fields
	wire := struct {
		*fields
		Target json.RawMessage `json:"target,omitempty"`
	}{fields: &decoded}
	if err := strictjson.Decode(data, &wire); err != nil {
		return err
	}
	if len(wire.Target) != 0 {
		selected, err := target.Decode(wire.Target)
		if err != nil {
			return err
		}
		decoded.Target = &selected
	}
	*result = Result(decoded)
	return nil
}
