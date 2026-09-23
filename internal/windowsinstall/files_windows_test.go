//go:build windows

package windowsinstall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeExactHandleRemoval(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "owned")
			data := []byte("task-owned bytes")
			var err error
			if kind == "directory" {
				err = os.Mkdir(path, 0700)
			} else {
				err = os.WriteFile(path, data, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			identity, err := fileIdentity(path)
			if err != nil {
				t.Fatal(err)
			}
			expected := File{Path: "owned", Kind: kind, Identity: identity}
			if kind == "file" {
				expected.Size, expected.SHA256 = int64(len(data)), digest(data)
			}
			if err := removeOwnedFile(path, expected); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("owned %s remains: %v", kind, err)
			}
		})
	}
}
