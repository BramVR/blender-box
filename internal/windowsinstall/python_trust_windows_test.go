//go:build windows

package windowsinstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pythonTrustFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	data, err := powerShell(context.Background(), `$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm(('O:'+$sid+'G:'+$sid+'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$sid+')'))
Set-Acl -LiteralPath $r.root -AclObject $acl
ConvertTo-Json -InputObject $sid -Compress`, map[string]string{"root": root})
	if err != nil {
		t.Fatal(err)
	}
	var sid string
	if err := json.Unmarshal(data, &sid); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "grandparent", "parent", "python")
	for _, relative := range []string{"Lib/venv/__init__.py", "Lib/os.py", "Lib/__pycache__/os.pyc", "DLLs/extension.pyd", "python311.dll", "python311.zip", "package/__init__.py", "Lib/site-packages/external/module.py"} {
		path := filepath.Join(home, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, home, sid
}

func grantPythonFixtureWriter(t *testing.T, path string) {
	t.Helper()
	_, err := powerShell(context.Background(), `$acl=Get-Acl -LiteralPath $r.path
$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-101-202-303-404')
$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::Write,[Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $r.path -AclObject $acl`, map[string]string{"path": path})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPythonTrustAuditRejectsUntrustedRuntimeWriters(t *testing.T) {
	for _, relative := range []string{"Lib/venv/__init__.py", "Lib/venv", "package/__init__.py", "Lib/__pycache__/os.pyc", "python311.dll", "python311.zip"} {
		t.Run(relative, func(t *testing.T) {
			_, home, sid := pythonTrustFixture(t)
			grantPythonFixtureWriter(t, filepath.Join(home, filepath.FromSlash(relative)))
			if err := auditPython(context.Background(), home, sid); err == nil || !strings.Contains(err.Error(), "Untrusted path writer") {
				t.Fatalf("unsafe runtime audit=%v", err)
			}
		})
	}
}

func TestPythonTrustAuditRunsBeforePython(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		_, home, sid := pythonTrustFixture(t)
		path := filepath.Join(home, "python.exe")
		if err := os.WriteFile(path, pythonPEFixture(t), 0600); err != nil {
			t.Fatal(err)
		}
		if unsafe {
			grantPythonFixtureWriter(t, filepath.Join(home, "Lib", "venv", "__init__.py"))
		}
		called := false
		machine := nativeMachine{pythonCommand: func(context.Context, string, []string, []byte, []string) ([]byte, error) {
			called = true
			return nil, errors.New("test stops before native Python execution")
		}}
		_, err := machine.python(context.Background(), path, sid)
		if err == nil || called == unsafe {
			t.Fatalf("unsafe=%t probe=%t error=%v", unsafe, called, err)
		}
	}
}

func TestPythonTrustAuditExcludesOnlySitePackagesContents(t *testing.T) {
	_, home, sid := pythonTrustFixture(t)
	grantPythonFixtureWriter(t, filepath.Join(home, "Lib", "site-packages", "external"))
	if err := auditPython(context.Background(), home, sid); err != nil {
		t.Fatal(err)
	}
	grantPythonFixtureWriter(t, filepath.Join(home, "Lib", "site-packages"))
	if err := auditPython(context.Background(), home, sid); err == nil {
		t.Fatal("untrusted excluded directory accepted")
	}
}

func TestPythonTrustAuditDoesNotExcludeOtherSitePackages(t *testing.T) {
	_, home, sid := pythonTrustFixture(t)
	path := filepath.Join(home, "site-packages")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	grantPythonFixtureWriter(t, path)
	if err := auditPython(context.Background(), home, sid); err == nil {
		t.Fatal("untrusted root package directory accepted")
	}
}

func TestPythonTrustAuditRejectsStartupRedirectors(t *testing.T) {
	for _, relative := range []string{"python._pth", "python311._pth", "PYTHON314._PTH", "pyvenv.cfg", "../pyvenv.cfg", "pybuilddir.txt", "../../Modules/Setup.local", "../../../Modules/Setup.local"} {
		t.Run(relative, func(t *testing.T) {
			_, home, sid := pythonTrustFixture(t)
			path := filepath.Join(home, filepath.FromSlash(relative))
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("outside"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := auditPython(context.Background(), home, sid); err == nil || !strings.Contains(err.Error(), "refused") {
				t.Fatalf("redirector audit=%v", err)
			}
		})
	}
}

func TestPythonTrustAuditProtectsAbsentMarkerParents(t *testing.T) {
	for _, relative := range []string{"grandparent/parent", "grandparent", "."} {
		t.Run(relative, func(t *testing.T) {
			root, home, sid := pythonTrustFixture(t)
			grantPythonFixtureWriter(t, filepath.Join(root, relative))
			if err := auditPython(context.Background(), home, sid); err == nil || !strings.Contains(err.Error(), "Untrusted path writer") {
				t.Fatalf("marker creation authority audit=%v", err)
			}
		})
	}
}

func TestPythonTrustAuditAcceptsProtectedExistingMarkerParent(t *testing.T) {
	for _, relative := range []string{"grandparent", "."} {
		t.Run(relative, func(t *testing.T) {
			root, home, sid := pythonTrustFixture(t)
			if err := os.Mkdir(filepath.Join(root, relative, "Modules"), 0700); err != nil {
				t.Fatal(err)
			}
			grantPythonFixtureWriter(t, filepath.Join(root, relative))
			if err := auditPython(context.Background(), home, sid); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPythonTrustAuditRequiresLocalLandmarks(t *testing.T) {
	for _, relative := range []string{"Lib/os.py", "DLLs"} {
		t.Run(relative, func(t *testing.T) {
			_, home, sid := pythonTrustFixture(t)
			path := filepath.Join(home, filepath.FromSlash(relative))
			if err := os.Rename(path, path+"-absent"); err != nil {
				t.Fatal(err)
			}
			if err := auditPython(context.Background(), home, sid); err == nil || !strings.Contains(err.Error(), "layout") {
				t.Fatalf("missing landmark audit=%v", err)
			}
		})
	}
}

func TestPythonTrustAuditHonorsCancellation(t *testing.T) {
	_, home, sid := pythonTrustFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := auditPython(ctx, home, sid); err == nil {
		t.Fatal("canceled audit succeeded")
	}
}

func TestPythonTrustAuditBounds(t *testing.T) {
	_, home, sid := pythonTrustFixture(t)
	for _, limits := range []struct {
		name                         string
		entries, depth, milliseconds int
	}{
		{"entry", 1, 64, 40000},
		{"depth", 32768, 0, 40000},
		{"deadline", 32768, 64, 0},
	} {
		t.Run(limits.name, func(t *testing.T) {
			_, err := powerShell(context.Background(), pythonTrustFunctions+`Assert-PythonTree $r.home $r.sid $r.entries $r.depth $r.milliseconds`, map[string]any{"home": home, "sid": sid, "entries": limits.entries, "depth": limits.depth, "milliseconds": limits.milliseconds})
			if err == nil || !strings.Contains(err.Error(), limits.name) {
				t.Fatalf("bound audit=%v", err)
			}
		})
	}
}

func TestPythonTrustAuditRejectsReparseDirectory(t *testing.T) {
	root, home, sid := pythonTrustFixture(t)
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "linked-package")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink privilege unavailable: %v", err)
	}
	if err := auditPython(context.Background(), home, sid); err == nil || !strings.Contains(err.Error(), "Reparse") {
		t.Fatalf("reparse audit=%v", err)
	}
}
