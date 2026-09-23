//go:build windows

package windowsinstall

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeSealedRuntimeACLAndExactRemoval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sid, err := fakeCurrentSID()
	if err != nil {
		t.Fatal(err)
	}
	machine := nativeMachine{}
	root := filepath.Join(t.TempDir(), "site-packages")
	packageDir := filepath.Join(root, "blendersessiond")
	for _, path := range []string{root, packageDir} {
		if err := machine.createDirectory(ctx, path, sid); err != nil {
			t.Fatalf("create managed directory %s: %v", path, err)
		}
	}
	contents := []byte("sealed runtime test\n")
	module := filepath.Join(packageDir, "__main__.py")
	if err := publishBytes(module, root, contents, false, nil); err != nil {
		t.Fatal(err)
	}
	files := []File{
		{Path: "site-packages/blendersessiond/__main__.py", Kind: "file", Size: int64(len(contents)), SHA256: digest(contents)},
		{Path: "site-packages/blendersessiond", Kind: "directory"},
		{Path: "site-packages", Kind: "directory"},
	}
	paths := []string{module, packageDir, root}
	for i := range files {
		files[i], err = observeFile(paths[i], files[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	checks := []runtimePathCheck{{Path: module}, {Path: packageDir}, {Path: root}}
	if err := machine.secureRuntimePaths(ctx, checks, sid); err != nil {
		t.Fatalf("unsealed ACL batch: %v", err)
	}
	for i := range files {
		if err := machine.sealPath(ctx, paths[i], sid); err != nil {
			t.Fatalf("seal %s: %v", paths[i], err)
		}
		planned := files[i]
		planned.Identity = ""
		sealed, err := observeFile(paths[i], planned)
		if err != nil {
			t.Fatal(err)
		}
		if sealed.Identity == files[i].Identity || !sameFileObject(files[i].Identity, sealed.Identity) {
			t.Fatalf("seal failed to preserve object and change security: %s", paths[i])
		}
		if err := machine.secureSealedPath(ctx, paths[i], sid); err != nil {
			t.Fatalf("sealed ACL rejected: %s: %v", paths[i], err)
		}
		files[i] = sealed
		checks[i].Sealed = true
		if err := machine.secureRuntimePaths(ctx, checks, sid); err != nil {
			t.Fatalf("mixed ACL batch after sealing %s: %v", paths[i], err)
		}
	}
	for i := range files {
		if err := removeOwnedFile(paths[i], files[i]); err != nil {
			t.Fatalf("exact removal of sealed object %s: %v", paths[i], err)
		}
		if _, err := os.Lstat(paths[i]); !os.IsNotExist(err) {
			t.Fatalf("sealed object retained after exact removal %s: %v", paths[i], err)
		}
	}
}
