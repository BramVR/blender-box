package windowsinstall

import "context"

// SSHRequest is the `setup ssh` operation: preview by default, apply against an exact plan, or
// remove what an earlier apply changed. It is deliberately separate from Request.
type SSHRequest struct {
	StateRoot       string         `json:"state_root"`
	InstallationID  InstallationID `json:"installation_id"`
	RemoteAddresses []string       `json:"remote_addresses"`
	Profiles        []string       `json:"profiles"`
	Remove          bool           `json:"remove"`
	Apply           bool           `json:"apply"`
	ExpectedPlan    SHA256         `json:"expected_plan"`
}
type ServiceChange struct {
	PriorStatus    string `json:"prior_status"`
	PriorStartType string `json:"prior_start_type"`
	Start          bool   `json:"start"`
	SetAutomatic   bool   `json:"set_automatic"`
}
type FirewallRule struct {
	Name            string   `json:"name"`
	Port            uint16   `json:"port"`
	Program         string   `json:"program"`
	Profiles        []string `json:"profiles"`
	RemoteAddresses []string `json:"remote_addresses"`
}
type SSHPlan struct {
	PlanSHA256    SHA256        `json:"plan_sha256"`
	Account       string        `json:"account"`
	Port          uint16        `json:"port"`
	Service       ServiceChange `json:"service"`
	Rule          *FirewallRule `json:"rule,omitempty"`
	AdmittingRule string        `json:"admitting_rule,omitempty"`
}
type SSHResult struct {
	SchemaVersion int       `json:"schema_version"`
	State         string    `json:"state"` // planned | unchanged | applied | removed | conflict
	Plan          SSHPlan   `json:"plan"`
	Problems      []Problem `json:"problems"`
}
type SSHPreparer interface {
	PrepareSSH(context.Context, SSHRequest) (SSHResult, error)
}
