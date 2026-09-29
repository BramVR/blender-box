package windowsinstall

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalExecutableExceedsRuntimeArtifactLimit(t *testing.T) {
	path := filepath.Join(tempRoot(t), "blender.exe")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(peFixture()); err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(maxArtifact + 1); err != nil {
		t.Fatal(err)
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	expected := sha256.New()
	if _, err = io.Copy(expected, file); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	hash, identity, err := hashPrerequisite(path, true)
	if err != nil || string(hash) != fmt.Sprintf("%x", expected.Sum(nil)) || identity == "" {
		t.Fatalf("external prerequisite hash=%s identity=%s error=%v", hash, identity, err)
	}
	if _, err := readSource(path); err == nil {
		t.Fatal("runtime artifact limit no longer enforced")
	}
}

func TestPrerequisiteRejectsUnsupportedSources(t *testing.T) {
	for _, test := range []struct{ kind, want string }{
		{"oversize", "at most 2 GiB"},
		{"directory", "regular file"},
		{"non-pe", "not PE"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			path := filepath.Join(tempRoot(t), "prerequisite")
			switch test.kind {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				// A valid PE header proves the size guard, not the PE parser, refuses it.
				if err := os.WriteFile(path, peFixture(), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(path, maxPrerequisite+1); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := hashPrerequisite(path, true); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}
