package windowsinstall

import (
	"context"
	"path/filepath"
	"testing"
)

func TestInstallTimingsCountEveryReceiptGenerationAndRuntimeFile(t *testing.T) {
	e, _, r := installFixture(t)
	r.Apply = true
	id, _ := newID("bbxi_")
	r.InstallationID = InstallationID(id)
	ctx, timer := withStepTimer(context.Background())
	installed, err := e.Execute(ctx, r)
	if err != nil || installed.State != "installed" {
		t.Fatalf("install=%+v error=%v", installed, err)
	}
	receipt, err := readReceipt(filepath.Join(r.StateRoot, "installations", id, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, file := range receipt.Files {
		if file.Kind == "file" {
			files++
		}
	}
	steps := map[string]int{}
	report := timer.report()
	for _, step := range report {
		steps[step.Step] = step.Calls
	}
	if steps["receipt"] != int(receipt.Generation) || steps["publish-file"] != files || steps["validate-owned"] == 0 {
		t.Fatalf("steps=%+v generation=%d files=%d", report, receipt.Generation, files)
	}
	if err := validateStepTimings(report); err != nil {
		t.Fatal(err)
	}
}

func TestStepTimingsRejectUnboundedOrMalformedEntries(t *testing.T) {
	valid := StepTiming{Step: "powershell", Calls: 3, Milliseconds: 4200}
	bounded := make([]StepTiming, maxStepTimings)
	for i := range bounded {
		bounded[i] = StepTiming{Step: "step-" + string(rune('a'+i/26)) + string(rune('a'+i%26)), Calls: 1}
	}
	if err := validateStepTimings(bounded); err != nil {
		t.Fatalf("bounded timings rejected: %v", err)
	}
	for name, steps := range map[string][]StepTiming{
		"excessive":     append(append([]StepTiming{}, bounded...), valid),
		"duplicate":     {valid, valid},
		"no-calls":      {{Step: "seal", Milliseconds: 1}},
		"negative-time": {{Step: "seal", Calls: 1, Milliseconds: -1}},
		"unsafe-name":   {{Step: "Seal Step", Calls: 1}},
		"empty-name":    {{Calls: 1}},
	} {
		if err := validateStepTimings(steps); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
