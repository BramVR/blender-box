package orchestrator

import (
	"context"
	"fmt"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/uiaction"
)

type PlanIntent struct {
	Target  target.Target
	Payload payload.Payload
}

type PlannedCapture struct {
	Kind             capture.Kind       `json:"kind"`
	Path             string             `json:"path"`
	Capability       capture.Capability `json:"capability"`
	PrivacySensitive bool               `json:"privacy_sensitive"`
}

type PlannedUIBatch struct {
	SchemaVersion  int    `json:"schema_version"`
	Count          int    `json:"count"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Capability     string `json:"capability"`
}
type UIActionSupport struct {
	Capability string `json:"capability"`
	Supported  bool   `json:"supported"`
}
type PlanResult struct {
	UIActions            *PlannedUIBatch  `json:"ui_actions,omitempty"`
	SchemaVersion        int              `json:"schema_version"`
	Status               string           `json:"status"`
	PayloadSchemaVersion int              `json:"payload_schema_version"`
	FileCount            int              `json:"file_count"`
	Captures             []PlannedCapture `json:"captures"`
	ExpectedEvidence     []EvidenceType   `json:"expected_evidence"`
}

type CaptureSupport struct {
	Kind       capture.Kind       `json:"kind"`
	Capability capture.Capability `json:"capability"`
	Supported  bool               `json:"supported"`
}

type HostInspection struct {
	UIActions     *UIActionSupport `json:"ui_actions,omitempty"`
	SchemaVersion int              `json:"schema_version"`
	Status        string           `json:"status"`
	Captures      []CaptureSupport `json:"captures"`
}

type HostRequirements struct {
	UIActions            bool
	PayloadSchemaVersion int
	Captures             []capture.Kind
}

type DoctorResult struct {
	SchemaVersion int            `json:"schema_version"`
	Status        string         `json:"status"`
	Plan          PlanResult     `json:"plan"`
	Host          HostInspection `json:"host"`
}

func (runner *Runner) Plan(intent PlanIntent) (PlanResult, error) {
	if err := intent.Target.Validate(); err != nil {
		return PlanResult{}, fmt.Errorf("invalid target: %w", err)
	}
	if err := intent.Payload.Validate(); err != nil {
		return PlanResult{}, fmt.Errorf("invalid payload: %w", err)
	}
	plan := PlanResult{
		SchemaVersion:        1,
		Status:               "pass",
		PayloadSchemaVersion: intent.Payload.SchemaVersion,
		FileCount:            len(intent.Payload.Files),
		ExpectedEvidence:     []EvidenceType{EvidenceScenarioResult},
	}
	if batch := intent.Payload.Scenario.UIActions; batch != nil {
		plan.UIActions = &PlannedUIBatch{SchemaVersion: batch.SchemaVersion, Count: len(batch.Actions), TimeoutSeconds: batch.TimeoutSeconds, Capability: uiaction.Capability}
		plan.ExpectedEvidence = append(plan.ExpectedEvidence, EvidenceUIActions)
	}
	for _, kind := range intent.Payload.Scenario.Captures() {
		definition, exists := capture.Describe(kind)
		if !exists {
			return PlanResult{}, fmt.Errorf("unsupported capture kind %q", kind)
		}
		plan.Captures = append(plan.Captures, PlannedCapture{
			Kind:             definition.Kind,
			Path:             definition.EvidencePath,
			Capability:       definition.Capability,
			PrivacySensitive: definition.PrivacySensitive,
		})
		if kind == capture.BlenderWindow && plan.UIActions != nil {
			plan.Captures[len(plan.Captures)-1].Path = uiaction.BeforePath
			after := plan.Captures[len(plan.Captures)-1]
			after.Path = uiaction.AfterPath
			plan.Captures = append(plan.Captures, after)
		}
		plan.ExpectedEvidence = append(plan.ExpectedEvidence, EvidenceType(kind))
	}
	return plan, nil
}

func (runner *Runner) Doctor(ctx context.Context, intent PlanIntent) (DoctorResult, error) {
	plan, err := runner.Plan(intent)
	if err != nil {
		return DoctorResult{}, err
	}
	if runner.host == nil {
		return DoctorResult{}, fmt.Errorf("host adapter is unavailable")
	}
	inspection, err := runner.host.Inspect(ctx, intent.Target, hostRequirements(plan))
	if err != nil {
		return DoctorResult{}, err
	}
	status := "fail"
	if inspectionSupports(inspection, plan.Captures) && uiInspectionSupports(inspection, plan.UIActions != nil) {
		status = "pass"
	}
	return DoctorResult{SchemaVersion: 1, Status: status, Plan: plan, Host: inspection}, nil
}

func plannedKinds(plan PlanResult) []capture.Kind {
	kinds := make([]capture.Kind, 0, len(plan.Captures))
	for _, planned := range plan.Captures {
		kinds = append(kinds, planned.Kind)
	}
	return kinds
}

func hostRequirements(plan PlanResult) HostRequirements {
	return HostRequirements{PayloadSchemaVersion: plan.PayloadSchemaVersion, Captures: plannedKinds(plan), UIActions: plan.UIActions != nil}
}

func inspectionSupports(inspection HostInspection, planned []PlannedCapture) bool {
	if inspection.SchemaVersion != 1 || inspection.Status != "pass" {
		return false
	}
	supported := make(map[capture.Kind]capture.Capability, len(inspection.Captures))
	for _, support := range inspection.Captures {
		if support.Supported {
			supported[support.Kind] = support.Capability
		}
	}
	for _, plannedCapture := range planned {
		if supported[plannedCapture.Kind] != plannedCapture.Capability {
			return false
		}
	}
	return true
}

func uiInspectionSupports(inspection HostInspection, required bool) bool {
	return !required || inspection.UIActions != nil && inspection.UIActions.Capability == uiaction.Capability && inspection.UIActions.Supported
}
