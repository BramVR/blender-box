package windowsinstall

import (
	"github.com/BramVR/blender-box/internal/target"
	"time"
)

type SSHPreparationRequest struct {
	SchemaVersion   int                `json:"schema_version"`
	Platform        string             `json:"platform"`
	InstallationID  InstallationID     `json:"installation_id"`
	OperationID     OperationID        `json:"operation_id"`
	StateRoot       string             `json:"state_root"`
	Account         string             `json:"account"`
	Connection      SSHConnectionScope `json:"connection"`
	ControlAccounts []string           `json:"control_accounts"`
	Deadline        time.Time          `json:"deadline"`
}
type SSHConnectionScope struct {
	Hostname         string   `json:"hostname"`
	Port             uint16   `json:"port"`
	LoginUser        string   `json:"login_user"`
	LocalAddresses   []string `json:"local_addresses"`
	RemotePrefixes   []string `json:"remote_prefixes"`
	FirewallProfiles []string `json:"firewall_profiles"`
}
type SSHPathPin struct {
	Path          string `json:"path"`
	PhysicalID    string `json:"physical_id"`
	DescriptorSHA SHA256 `json:"descriptor_sha256"`
}
type SSHFilePin struct {
	Path     SSHPathPin `json:"path"`
	Size     int64      `json:"size"`
	BytesSHA SHA256     `json:"bytes_sha256"`
}
type SSHByteImage struct {
	Pin   SSHFilePin `json:"pin"`
	Bytes []byte     `json:"bytes"`
}
type SSHInstalledScope struct {
	Receipt          SSHByteImage  `json:"receipt"`
	Root             SSHPathPin    `json:"root"`
	AccountSID       string        `json:"account_sid"`
	InteractiveSID   string        `json:"interactive_sid"`
	AuthenticatedSID string        `json:"authenticated_sid"`
	Target           target.Target `json:"target"`
	RuntimeFiles     []SSHFilePin  `json:"runtime_files"`
	TaskFingerprint  SHA256        `json:"task_fingerprint"`
}
type SSHConfigurationChange struct {
	Before       SSHByteImage `json:"before"`
	InsertOffset int64        `json:"insert_offset"`
	InsertBytes  []byte       `json:"insert_bytes"`
	AfterBytes   []byte       `json:"after_bytes"`
	AfterSHA     SHA256       `json:"after_sha256"`
}
type SSHSourceProposal struct {
	Parent        SSHPathPin `json:"parent"`
	Directory     string     `json:"directory"`
	File          string     `json:"file"`
	Receipt       string     `json:"receipt"`
	Pending       string     `json:"pending"`
	Stage         string     `json:"stage"`
	DirectorySDDL string     `json:"directory_sddl"`
	FileSDDL      string     `json:"file_sddl"`
	InitialBytes  []byte     `json:"initial_bytes"`
}
type SSHEffectivePolicy struct {
	Account             string   `json:"account"`
	SID                 string   `json:"sid"`
	Administrator       bool     `json:"administrator"`
	Groups              []string `json:"groups"`
	NativeBefore        []byte   `json:"native_before"`
	BeforeSHA           SHA256   `json:"before_sha256"`
	PredictedAfter      []byte   `json:"predicted_after"`
	AfterSHA            SHA256   `json:"after_sha256"`
	PriorSources        []string `json:"prior_sources"`
	NativeProofRequired bool     `json:"native_proof_required"`
}
type SSHServiceState struct {
	InstallationProvenance string     `json:"installation_provenance"`
	OSBuild                string     `json:"os_build"`
	Name                   string     `json:"name"`
	Binary                 SSHFilePin `json:"binary"`
	BinaryVersion          string     `json:"binary_version"`
	CommandLine            string     `json:"command_line"`
	Account                string     `json:"account"`
	StartType              string     `json:"start_type"`
	State                  string     `json:"state"`
	ServiceSDDL            string     `json:"service_sddl"`
	Activation             string     `json:"activation"`
	RequiredPrivilege      string     `json:"required_privilege"`
}
type SSHFirewallRule struct {
	PolicyStore     string   `json:"policy_store"`
	ID              string   `json:"id"`
	Enabled         bool     `json:"enabled"`
	Direction       string   `json:"direction"`
	Action          string   `json:"action"`
	Profiles        []string `json:"profiles"`
	Protocol        string   `json:"protocol"`
	LocalAddresses  []string `json:"local_addresses"`
	LocalPorts      []string `json:"local_ports"`
	RemoteAddresses []string `json:"remote_addresses"`
	RemotePorts     []string `json:"remote_ports"`
	Program         string   `json:"program"`
	Service         string   `json:"service"`
	InterfaceTypes  []string `json:"interface_types"`
	EdgeTraversal   string   `json:"edge_traversal"`
}
type SSHHostKeyPin struct {
	PrivateSource SSHPathPin   `json:"private_source"`
	PublicSource  SSHByteImage `json:"public_source"`
	PublicKey     string       `json:"public_key"`
	PublicSHA     SHA256       `json:"public_sha256"`
	Provenance    string       `json:"provenance"`
}
type SSHPreparationPlanBody struct {
	SchemaVersion  int                    `json:"schema_version"`
	Request        SSHPreparationRequest  `json:"request"`
	RequestSHA256  SHA256                 `json:"request_sha256"`
	Installed      SSHInstalledScope      `json:"installed"`
	Configuration  SSHConfigurationChange `json:"configuration"`
	Source         SSHSourceProposal      `json:"source"`
	Policies       []SSHEffectivePolicy   `json:"policies"`
	Service        SSHServiceState        `json:"service"`
	Keygen         SSHFilePin             `json:"keygen"`
	HostKeys       []SSHHostKeyPin        `json:"host_keys"`
	Firewall       []SSHFirewallRule      `json:"firewall"`
	FirewallChange string                 `json:"firewall_change"`
	ReversalLimit  string                 `json:"reversal_limit"`
	PolicyProof    string                 `json:"policy_proof"`
}
type SSHPreparationPlan struct {
	PlanSHA256 SHA256                 `json:"plan_sha256"`
	Body       SSHPreparationPlanBody `json:"body"`
}
type SSHPreparationPreviewResult struct {
	SchemaVersion int                 `json:"schema_version"`
	State         string              `json:"state"`
	Plan          *SSHPreparationPlan `json:"plan,omitempty"`
	Problems      []Problem           `json:"problems"`
}
