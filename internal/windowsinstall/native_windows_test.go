//go:build windows

package windowsinstall

import (
	"context"
	"testing"

	"github.com/BramVR/blender-box/internal/strictjson"
)

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
