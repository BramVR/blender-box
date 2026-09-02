package payload

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadResolvesAndHashesDeclaredFiles(t *testing.T) {
	root := t.TempDir()
	script := []byte("print('slice 0')\n")
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), script, 0o600); err != nil {
		t.Fatal(err)
	}
	document := `{
  "schema_version": 1,
  "files": [{"source": "scenario.py", "destination": "scenario/scenario.py"}],
  "scenario": {"script": "scenario/scenario.py", "read_timeout_seconds": 600, "capture_viewport": true}
}`
	path := filepath.Join(root, "payload.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Files) != 1 {
		t.Fatalf("files = %d", len(loaded.Files))
	}
	file := loaded.Files[0]
	wantHash := sha256.Sum256(script)
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if file.LocalPath != filepath.Join(canonicalRoot, "scenario.py") || file.Size != int64(len(script)) || file.SHA256 != fmt.Sprintf("%x", wantHash) {
		t.Fatalf("loaded file = %+v", file)
	}
	if got := file.Contents(); string(got) != string(script) {
		t.Fatalf("contents = %q", got)
	}
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("changed after validation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := file.Contents(); string(got) != string(script) {
		t.Fatalf("snapshot changed with source = %q", got)
	}
	if err := loaded.Validate(); err != nil {
		t.Fatalf("validated snapshot no longer valid: %v", err)
	}
}

func TestLoadRejectsUnsafeOrUnboundedPayloads(t *testing.T) {
	tests := []struct {
		name      string
		document  string
		prepare   func(*testing.T, string)
		wantError string
	}{
		{
			name:      "unknown field",
			document:  `{"schema_version":1,"files":[],"scenario":{"script":"scenario.py"},"surprise":true}`,
			wantError: "unknown field",
		},
		{
			name:      "destination traversal",
			document:  `{"schema_version":1,"files":[{"source":"scenario.py","destination":"../scenario.py"}],"scenario":{"script":"scenario.py"}}`,
			prepare:   writeScenario,
			wantError: "destination",
		},
		{
			name:     "source symlink",
			document: `{"schema_version":1,"files":[{"source":"link.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py"}}`,
			prepare: func(t *testing.T, root string) {
				writeScenario(t, root)
				if err := os.Symlink(filepath.Join(root, "scenario.py"), filepath.Join(root, "link.py")); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "regular file",
		},
		{
			name:      "scenario not declared",
			document:  `{"schema_version":1,"files":[{"source":"scenario.py","destination":"other.py"}],"scenario":{"script":"scenario.py"}}`,
			prepare:   writeScenario,
			wantError: "scenario script",
		},
		{
			name:      "timeout over daemon maximum",
			document:  `{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py","read_timeout_seconds":3601}}`,
			prepare:   writeScenario,
			wantError: "read timeout",
		},
		{
			name:      "Windows volume path",
			document:  `{"schema_version":1,"files":[{"source":"scenario.py","destination":"C:/temp/scenario.py"}],"scenario":{"script":"scenario.py"}}`,
			prepare:   writeScenario,
			wantError: "destination",
		},
		{
			name:      "NTFS alternate stream",
			document:  `{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py:stream"}],"scenario":{"script":"scenario.py:stream"}}`,
			prepare:   writeScenario,
			wantError: "scenario script",
		},
		{
			name:      "Windows reserved name",
			document:  `{"schema_version":1,"files":[{"source":"scenario.py","destination":"CON.py"}],"scenario":{"script":"CON.py"}}`,
			prepare:   writeScenario,
			wantError: "scenario script",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.prepare != nil {
				test.prepare(t, root)
			}
			path := filepath.Join(root, "payload.json")
			if err := os.WriteFile(path, []byte(test.document), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestValidateRejectsForgedPayload(t *testing.T) {
	forged := Payload{
		SchemaVersion: 1,
		Files: []File{{
			Source:      "scenario.py",
			Destination: "scenario.py",
			Size:        5,
			SHA256:      strings.Repeat("0", 64),
			LocalPath:   filepath.Join(t.TempDir(), "scenario.py"),
		}},
		Scenario: Scenario{Script: "scenario.py", ReadTimeoutSeconds: 180},
	}
	if err := forged.Validate(); err == nil || !strings.Contains(err.Error(), "validated contents") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadPinsSymlinkedDocumentRootToCanonicalPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating an unprivileged symlink is not portable on Windows")
	}
	parent := t.TempDir()
	actual := filepath.Join(parent, "actual")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	writeScenario(t, actual)
	document := `{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py"}}`
	if err := os.WriteFile(filepath.Join(actual, "payload.json"), []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(parent, "linked")
	if err := os.Symlink(actual, linked); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(filepath.Join(linked, "payload.json"))
	if err != nil {
		t.Fatal(err)
	}
	canonicalActual, err := filepath.EvalSymlinks(actual)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Files[0].LocalPath != filepath.Join(canonicalActual, "scenario.py") {
		t.Fatalf("source root was not pinned: %q", loaded.Files[0].LocalPath)
	}
}

func TestFileInfoStableDetectsSameSizeChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenario.py")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	changedTime := before.ModTime().Add(time.Second)
	if err := os.Chtimes(path, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfoStable(before, after) {
		t.Fatal("same-size metadata change accepted")
	}
}

func writeScenario(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
