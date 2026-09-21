package privatefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestAtomicReadersNeverSeePartialRecords(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	a := bytes.Repeat([]byte("a"), 64<<10)
	b := bytes.Repeat([]byte("b"), 64<<10)
	if err := Publish(root, "records/value", a, false); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 20; j++ {
				content := a
				if j%2 == 0 {
					content = b
				}
				if err := Publish(root, "records/value", content, true); err != nil {
					t.Error(err)
					return
				}
				data, err := Read(root, "records/value", 64<<10)
				if err != nil || !bytes.Equal(data, a) && !bytes.Equal(data, b) {
					t.Errorf("partial publication: %v", err)
					return
				}
			}
		}()
	}
	group.Wait()
	entries, err := os.ReadDir(filepath.Join(root, "records"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary cleanup %v %v", entries, err)
	}
}
func TestStorageRejectsUnsafeAndOversizedRecords(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if err := Publish(root, "records/value", []byte("original"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, "records/value", 2); err == nil {
		t.Fatal("oversized read accepted")
	}
	if err := Publish(root, "records/value", []byte("changed"), false); !os.IsExist(err) {
		t.Fatalf("exclusive create error=%v", err)
	}
	if data, err := Read(root, "records/value", 100); err != nil || string(data) != "original" {
		t.Fatal("failed publication changed prior state")
	}
	if err := os.Mkdir(filepath.Join(root, "records", "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, "records/directory", 100); err == nil {
		t.Fatal("directory accepted as record")
	}
	if err := Publish(root, "records/directory", []byte("changed"), true); err == nil {
		t.Fatal("directory replaced")
	}
	source := filepath.Join(root, "records", "value")
	link := filepath.Join(root, "records", "link")
	if err := os.Symlink(source, link); err == nil {
		if _, err := Read(root, "records/link", 100); err == nil {
			t.Fatal("symlink read")
		}
		if err := Publish(root, "records/link", []byte("changed"), true); err == nil {
			t.Fatal("symlink replaced")
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(source, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(root, "records/value", 100); err == nil {
			t.Fatal("public record accepted")
		}
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := Publish(root, "new/value", []byte("changed"), false); err == nil {
			t.Fatal("unsafe root accepted")
		}
		info, _ := os.Stat(root)
		if info.Mode().Perm() != 0o755 {
			t.Fatal("unsafe root permissions were rewritten")
		}
	}
}
func TestMissingStorageReadsStayReadOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if _, err := Read(root, "records/value", 100); !os.IsNotExist(err) {
		t.Fatalf("missing read=%v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("read created root")
	}
}

func TestDirectoryPublicationFlushesAncestorsAndPropagatesFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "new", "private")
	records := filepath.Join(root, "runs")
	flushed := map[string]bool{}
	if err := syncParents(records, func(path string) error {
		flushed[path] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, ancestor := range []string{root, filepath.Dir(root), filepath.Dir(filepath.Dir(root))} {
		if !flushed[ancestor] {
			t.Fatalf("directory entry not persisted in %s", ancestor)
		}
	}
	failure := errors.New("directory sync failed")
	if err := syncParents(records, func(string) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("directory durability failure lost: %v", err)
	}
}

func TestVisibleAuthorityRequiresDurabilityBeforeReadAcceptance(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	records, err := Directory(root, "runs", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(records, "claim.json"), []byte("complete authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("pending publication sync failed")
	data, err := readDurable(root, filepath.Join("runs", "claim.json"), 100, func(string) error { return failure })
	if !errors.Is(err, failure) || data != nil {
		t.Fatalf("unflushed authority accepted: %q %v", data, err)
	}
	flushed := map[string]bool{}
	data, err = readDurable(root, filepath.Join("runs", "claim.json"), 100, func(path string) error {
		flushed[path] = true
		return nil
	})
	if err != nil || string(data) != "complete authority" || !flushed[records] || !flushed[root] {
		t.Fatalf("reader did not establish publication durability: %q %v %v", data, err, flushed)
	}
}
