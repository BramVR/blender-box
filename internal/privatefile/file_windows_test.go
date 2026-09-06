//go:build windows

package privatefile

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementPreservesOpenReader(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	relative := filepath.Join("records", "value")
	original := bytes.Repeat([]byte("a"), 64<<10)
	replacement := bytes.Repeat([]byte("b"), 64<<10)
	if err := Publish(root, relative, original, false); err != nil {
		t.Fatal(err)
	}
	reader, err := openRead(filepath.Join(root, relative))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := Publish(root, relative, replacement, true); err != nil {
		t.Fatalf("replace with an open reader: %v", err)
	}
	if data, err := io.ReadAll(reader); err != nil || !bytes.Equal(data, original) {
		t.Fatalf("open reader lost original record: bytes=%d error=%v", len(data), err)
	}
	if data, err := Read(root, relative, 64<<10); err != nil || !bytes.Equal(data, replacement) {
		t.Fatalf("fresh reader missed replacement: bytes=%d error=%v", len(data), err)
	}
	if err := Publish(root, relative, original, false); !os.IsExist(err) {
		t.Fatalf("exclusive publication accepted existing record: %v", err)
	}
	if data, err := Read(root, relative, 64<<10); err != nil || !bytes.Equal(data, replacement) {
		t.Fatalf("exclusive publication changed record: bytes=%d error=%v", len(data), err)
	}
}

func TestReplacementRejectsReadOnlyDestination(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	relative := filepath.Join("records", "value")
	original := []byte("original")
	if err := Publish(root, relative, original, false); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, relative)
	if err := os.Chmod(destination, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(destination, 0o600); err != nil {
			t.Error(err)
		}
	})
	if err := Publish(root, relative, []byte("replacement"), true); !os.IsPermission(err) {
		t.Fatalf("read-only destination error: %v", err)
	}
	if data, err := Read(root, relative, 64<<10); err != nil || !bytes.Equal(data, original) {
		t.Fatalf("failed replacement changed record: %q error=%v", data, err)
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil || len(entries) != 1 || entries[0].Name() != "value" {
		t.Fatalf("failed replacement left temporary files: %v error=%v", entries, err)
	}
}
