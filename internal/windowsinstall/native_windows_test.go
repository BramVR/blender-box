//go:build windows

package windowsinstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/strictjson"
)

func TestNativeInspectionStatusAndRemovalWithoutPrerequisites(t *testing.T) {
	if os.Getenv("BLENDER_BOX_NATIVE_INSPECT_TEST") != "1" {
		t.Skip("set BLENDER_BOX_NATIVE_INSPECT_TEST=1 on Windows with the current account logged into the desktop and UAC enabled")
	}
	ctx := context.Background()
	machine := nativeMachine{}
	request := Request{Operation: "remove", StateRoot: filepath.Join(t.TempDir(), "state")}
	initial, err := machine.inspect(ctx, request)
	if err != nil {
		t.Fatalf("native account and root preconditions: %v", err)
	}
	if err := machine.createDirectory(ctx, request.StateRoot, initial.OwnerSID); err != nil {
		t.Fatal(err)
	}
	rootIdentity, err := fileIdentity(request.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	request.BlenderPath = filepath.Join(request.StateRoot, "missing-blender.exe")
	request.PythonPath = filepath.Join(request.StateRoot, "missing-python.exe")
	for _, operation := range []string{"status", "remove", "install", "inspect"} {
		t.Run(operation, func(t *testing.T) {
			request.Operation = operation
			inspection, err := machine.inspect(ctx, request)
			if inspection.OwnerSID != initial.OwnerSID || inspection.RootIdentity != rootIdentity {
				t.Fatalf("account or root inspection missing: %+v", inspection)
			}
			if operation == "status" || operation == "remove" {
				if err != nil {
					t.Fatalf("observation requires missing prerequisites: %v", err)
				}
				if len(inspection.BlenderCandidates) != 0 || inspection.Python != nil {
					t.Fatalf("unexpected prerequisite inspection: %+v", inspection)
				}
			} else if err == nil || !strings.Contains(err.Error(), "Required path missing") {
				t.Fatalf("missing prerequisite must fail inspection: %v", err)
			}
		})
	}
}

func TestNativeTaskNormalizationRejectsChangedValues(t *testing.T) {
	output, err := powerShell(context.Background(), `$first='<Task><Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings></Task>'
$reordered='<Task><Settings> <ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled> </Settings></Task>'
$changed='<Task><Settings><Enabled>true</Enabled><ExecutionTimeLimit>PT1H</ExecutionTimeLimit></Settings></Task>'
$sid='S-1-5-21-100-200-300-400'
$a='O:'+$sid+'G:'+$sid+'D:P(A;;FA;;;SY)(A;;FA;;;'+$sid+')'
$b='O:'+$sid+'G:'+$sid+'D:P(A;;GA;;;'+$sid+')(A;;FA;;;SY)'
$c='O:'+$sid+'G:'+$sid+'D:P(A;;FA;;;SY)(A;;FA;;;WD)'
[ordered]@{same_xml=((Canonical-XML $first) -ceq (Canonical-XML $reordered));changed_xml=((Canonical-XML $first) -cne (Canonical-XML $changed));same_security=((Canonical-Security $a) -ceq (Canonical-Security $b));changed_security=((Canonical-Security $a) -cne (Canonical-Security $c))}|ConvertTo-Json -Compress`, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		SameXML         bool `json:"same_xml"`
		ChangedXML      bool `json:"changed_xml"`
		SameSecurity    bool `json:"same_security"`
		ChangedSecurity bool `json:"changed_security"`
	}
	if err := strictjson.Decode(output, &result); err != nil {
		t.Fatal(err)
	}
	if !result.SameXML || !result.ChangedXML || !result.SameSecurity || !result.ChangedSecurity {
		t.Fatalf("normalization=%s", output)
	}
}
