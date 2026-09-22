//go:build windows

package windowsinstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestNativeTaskRegistrationRoundTrip(t *testing.T) {
	if os.Getenv("BLENDER_BOX_NATIVE_TASK_TEST") != "1" {
		t.Skip("set BLENDER_BOX_NATIVE_TASK_TEST=1 to authorize fresh limited interactive task registration and exact deletion; tasks are never run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	machine := nativeMachine{}
	inspection, err := machine.inspect(ctx, Request{Operation: "status", StateRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pin, err := openPinnedSource(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	for _, kind := range []string{"installation", "launcher"} {
		t.Run(kind, func(t *testing.T) {
			id, err := newID("bbxi_")
			if err != nil {
				t.Fatal(err)
			}
			spec := taskSpec{Name: "BlenderBox-RegistrationTest-" + id, OwnerSID: inspection.OwnerSID, InstallationID: InstallationID(id), Executable: executable, Arguments: "-test.run=^$", Directory: filepath.Dir(executable)}
			if kind == "launcher" {
				spec.Marker = "Blender Box registration test " + id
				spec.ExecutionTimeLimit = "PT6M"
			}
			created, err := machine.task(ctx, "create", spec)
			if err != nil || !created.Exists || !created.Matches || created.Running || !hex64.MatchString(string(created.Fingerprint)) {
				t.Fatalf("registration not confirmed; preserve task %s for inspection: %+v %v", spec.Name, created, err)
			}
			deleteSubmitted := false
			t.Cleanup(func() {
				if deleteSubmitted {
					return
				}
				cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				current, err := machine.task(cleanup, "inspect", spec)
				if err != nil || !current.Exists || !current.Matches || current.Running || current.Fingerprint != created.Fingerprint {
					t.Errorf("cannot clean changed or uncertain task %s: %+v %v", spec.Name, current, err)
					return
				}
				removed, err := machine.task(cleanup, "delete", spec)
				if err != nil || removed.Exists {
					t.Errorf("cleanup unknown for task %s: %+v %v", spec.Name, removed, err)
				}
			})
			observed, err := machine.task(ctx, "inspect", spec)
			if err != nil || observed != created {
				t.Fatalf("registered task differs on fresh inspection: %+v %v", observed, err)
			}
			changed := spec
			changed.Arguments = "-test.run=^NoSuchTaskDefinitionTest$"
			mismatch, err := machine.task(ctx, "inspect", changed)
			if err != nil || !mismatch.Exists || mismatch.Matches || mismatch.Fingerprint != created.Fingerprint {
				t.Fatalf("changed action matched: %+v %v", mismatch, err)
			}
			if _, err := machine.task(ctx, "delete", changed); err == nil {
				t.Fatal("changed action authorized task deletion")
			}
			observed, err = machine.task(ctx, "inspect", spec)
			if err != nil || observed != created {
				t.Fatalf("refused deletion changed original task: %+v %v", observed, err)
			}
			deleteSubmitted = true
			removed, err := machine.task(ctx, "delete", spec)
			if err != nil || removed.Exists {
				t.Fatalf("exact task deletion not confirmed: %+v %v", removed, err)
			}
			absent, err := machine.task(ctx, "inspect", spec)
			if err != nil || absent.Exists {
				t.Fatalf("deleted task remains: %+v %v", absent, err)
			}
		})
	}
}
