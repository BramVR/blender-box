//go:build !windows

package linuxruntime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSafePathRejectsRelativePathsBeforeTraversal(t *testing.T) {
	if os.Getenv("BLENDER_BOX_SAFE_PATH_PROBE") == "1" {
		for _, name := range []string{"", ".", "./", "child", "../child"} {
			if err := SafePath(name, uint32(os.Geteuid()), true); err == nil || !strings.Contains(err.Error(), "path must be absolute") {
				t.Fatalf("relative path %q: %v", name, err)
			}
		}
		return
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSafePathRejectsRelativePathsBeforeTraversal$")
	command.Dir = root
	command.Env = append(os.Environ(), "BLENDER_BOX_SAFE_PATH_PROBE=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("relative-path validation did not finish successfully: %v\n%s", err, output)
	}
}

func TestSafePathRejectsNonCanonicalNamesAndNonPrivateLeaf(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o700, 0o755} {
		if err := os.Chmod(root, mode); err != nil {
			t.Fatal(err)
		}
		err := SafePath(root, uint32(os.Geteuid()), true)
		if mode == 0o700 && err != nil || mode == 0o755 && (err == nil || !strings.Contains(err.Error(), "owner-only")) {
			t.Fatalf("mode=%o path=%q: %v", mode, root, err)
		}
		for _, name := range []string{root + "/", root + "/.", root + "/child/.."} {
			if err := SafePath(name, uint32(os.Geteuid()), true); err == nil || !strings.Contains(err.Error(), "must be canonical") {
				t.Fatalf("noncanonical path %q: %v", name, err)
			}
		}
	}
}
