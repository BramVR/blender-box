package linuxruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/linuxtarget"
)

func TestCleanEnvironmentProtectsRecursivePythonImports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux/POSIX environment contract")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	venv := filepath.Join(root, "venv")
	create := exec.CommandContext(ctx, python, "-I", "-B", "-m", "venv", "--without-pip", "--copies", venv)
	if output, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create task-local venv: %v %s", err, output)
	}
	executable := filepath.Join(venv, "bin", "python3")
	if runtime.GOOS == "windows" {
		executable = filepath.Join(venv, "Scripts", "python.exe")
	}
	probe := exec.CommandContext(ctx, executable, "-I", "-B", "-c", "import sys,sysconfig; assert sys.version_info >= (3,11); print(sysconfig.get_path('purelib'))")
	site, err := probe.Output()
	if err != nil {
		t.Skip("recursive safety flags require Python 3.11 or later")
	}
	moduleRoot := filepath.Join(strings.TrimSpace(string(site)), "bbx_import_fixture")
	if err := os.Mkdir(moduleRoot, 0700); err != nil {
		t.Fatal(err)
	}
	code := `import json,os,subprocess,sys
level=int(sys.argv[1])
items=json.loads(subprocess.check_output([sys.executable,"-m","bbx_import_fixture",str(level-1)])) if level else []
items.append({"file":__file__,"safe":sys.flags.safe_path,"bytecode":sys.dont_write_bytecode,"user_site":os.environ.get("PYTHONNOUSERSITE"),"pythonpath":os.environ.get("PYTHONPATH")})
print(json.dumps(items))
`
	if err := os.WriteFile(filepath.Join(moduleRoot, "__main__.py"), []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(root, "decoy")
	if err := os.Mkdir(decoy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(decoy, "bbx_import_fixture.py"), []byte("raise RuntimeError('untrusted cwd import')"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, executable, "-I", "-B", "-m", "bbx_import_fixture", "2")
	command.Dir = decoy
	command.Env = CleanEnvironment(map[string]string{"HOME": root, "PYTHONPATH": decoy, "PYTHONHOME": decoy})
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("recursive import: %v %s", err, output)
	}
	var results []struct {
		File       string  `json:"file"`
		Safe       bool    `json:"safe"`
		Bytecode   bool    `json:"bytecode"`
		UserSite   string  `json:"user_site"`
		PythonPath *string `json:"pythonpath"`
	}
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("recursive results = %s", output)
	}
	for _, result := range results {
		if result.File != filepath.Join(moduleRoot, "__main__.py") || !result.Safe || !result.Bytecode || result.UserSite != "1" || result.PythonPath != nil {
			t.Fatalf("unsafe recursive import %+v", result)
		}
	}
	if _, err := os.Stat(filepath.Join(moduleRoot, "__pycache__")); !os.IsNotExist(err) {
		t.Fatalf("recursive daemon wrote bytecode: %v", err)
	}
}
func TestCompiledRuntimeManifestPinsCompleteReviewedCorrection(t *testing.T) {
	var manifest struct {
		Base   string            `json:"base_commit"`
		Fix    string            `json:"fix_patch_sha256"`
		Files  map[string]string `json:"package_files"`
		Scope  string            `json:"proof_scope"`
		Native bool              `json:"native_linux_proof"`
	}
	if err := json.Unmarshal(provenance, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Base != "6d40e40376897b09c18fc13c60296d37c5bef2ba" || manifest.Fix != "9a54bfb9bd0b44690acaed32da52cca3f285781cdaa481c5c089576dc7013721" || len(manifest.Files) != 20 || manifest.Native || manifest.Scope != "PASS_SHARED_POSIX_FAKE" {
		t.Fatalf("unexpected reviewed provenance %+v", manifest)
	}
	for _, name := range []string{"posix_launcher.py", "processes.py", "vendor/addon.py", "vendor/addon.patch"} {
		if len(manifest.Files[name]) != 64 {
			t.Fatalf("missing reviewed %s", name)
		}
	}
}
func TestRuntimeTreeRefusesImportDrift(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX filesystem policy")
	}
	cases := []struct {
		name, path string
		contents   []byte
		link       bool
	}{
		{"pth", "lib/python3.12/site-packages/unsafe.pth", []byte("import evil"), false},
		{"customization", "lib/python3.12/site-packages/sitecustomize.py", []byte("raise RuntimeError()"), false},
		{"extra package", "lib/python3.12/site-packages/extra.py", []byte(""), false},
		{"bytecode", "lib/python3.12/site-packages/blendersessiond/__pycache__/cached.pyc", []byte("cache"), false},
		{"changed package", "lib/python3.12/site-packages/blendersessiond/__init__.py", []byte("changed"), false},
		{"symlink", "lib/python3.12/site-packages/link.py", nil, true},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			selected, pythonHash, hashes := fakeRuntimeTree(t)
			if err := verifyContents(selected, uint32(os.Getuid()), pythonHash, hashes); err != nil {
				t.Fatalf("baseline fixture: %v", err)
			}
			name := filepath.Join(selected.VenvRoot, item.path)
			if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
				t.Fatal(err)
			}
			if item.link {
				if err := os.Symlink(selected.PythonExecutable, name); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(name, item.contents, 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyContents(selected, uint32(os.Getuid()), pythonHash, hashes); err == nil {
				t.Fatal("unsafe import tree accepted")
			}
		})
	}
}
func TestVenvConfigSymlinkRefusesBeforeInterpreterProbe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX filesystem policy")
	}
	selected, _, _ := fakeRuntimeTree(t)
	cfg := filepath.Join(selected.VenvRoot, "pyvenv.cfg")
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/does-not-exist", cfg); err != nil {
		t.Fatal(err)
	}
	if err := verifyTree(selected, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "unsafe Linux path") {
		t.Fatalf("cfg link error = %v", err)
	}
}
func fakeRuntimeTree(t *testing.T) (linuxtarget.DaemonRuntime, string, map[string]string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"bin", "lib/python3.12/site-packages/blendersessiond"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	binary := []byte("copied interpreter fixture")
	source := []byte("# reviewed fixture\n")
	for name, data := range map[string][]byte{"bin/python3": binary, "pyvenv.cfg": []byte("include-system-site-packages = false\nhome = /usr/bin\nversion = 3.12.3\nexecutable = /usr/bin/python3.12\n"), "lib/python3.12/site-packages/blendersessiond/__init__.py": source} {
		mode := os.FileMode(0600)
		if name == "bin/python3" {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(root, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	pythonHash := sha256.Sum256(binary)
	packageHash := sha256.Sum256(source)
	return linuxtarget.DaemonRuntime{VenvRoot: root, PythonExecutable: root + "/bin/python3", ProvenanceID: linuxtarget.ProvenanceID}, hex.EncodeToString(pythonHash[:]), map[string]string{"__init__.py": hex.EncodeToString(packageHash[:])}
}
