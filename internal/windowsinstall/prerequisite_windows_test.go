//go:build windows

package windowsinstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrerequisiteBatchRefusesWholeBatchOnAnyRefusal(t *testing.T) {
	for _, change := range []string{"none", "untrusted-middle", "missing-middle", "untrusted-last"} {
		t.Run(change, func(t *testing.T) {
			_, home, sid := pythonTrustFixture(t)
			image := pythonPEFixture(t)
			checks := []prerequisiteCheck{
				{Path: filepath.Join(home, "first.exe"), Executable: true},
				{Path: filepath.Join(home, "second.exe"), Executable: true},
				{Path: filepath.Join(home, "python311.dll")},
			}
			for _, check := range checks[:2] {
				if err := os.WriteFile(check.Path, image, 0600); err != nil {
					t.Fatal(err)
				}
			}
			refusal := map[string][2]string{
				"untrusted-middle": {checks[1].Path, "Untrusted path writer"},
				"missing-middle":   {checks[1].Path, "Required path missing"},
				"untrusted-last":   {checks[2].Path, "Untrusted path writer"},
			}[change]
			refused, reason := refusal[0], refusal[1]
			switch change {
			case "untrusted-middle", "untrusted-last":
				grantPythonFixtureWriter(t, refused)
			case "missing-middle":
				if err := os.Remove(refused); err != nil {
					t.Fatal(err)
				}
			}
			found, err := nativeMachine{}.candidates(context.Background(), sid, checks, "")
			if change != "none" {
				if err == nil || !strings.Contains(err.Error(), refused+": "+reason) || found != nil {
					t.Fatalf("refused batch member accepted: found=%+v err=%v", found, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(found) != 3 {
				t.Fatalf("candidates=%+v", found)
			}
			for i, want := range []SHA256{digest(image), digest(image), digest([]byte("fixture"))} {
				identity, err := fileIdentity(checks[i].Path)
				if err != nil {
					t.Fatal(err)
				}
				if found[i].Path != checks[i].Path || found[i].SHA256 != want || found[i].Identity != identity || found[i].Version != "" {
					t.Fatalf("candidate %d=%+v", i, found[i])
				}
			}
		})
	}
}
