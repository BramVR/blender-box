package payload

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if file.LocalPath != filepath.Join(root, "scenario.py") || file.Size != int64(len(script)) || file.SHA256 != fmt.Sprintf("%x", wantHash) {
		t.Fatalf("loaded file = %+v", file)
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

func writeScenario(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
