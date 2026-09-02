package ssh

import (
	"reflect"
	"testing"
)

func TestBoundedBufferKeepsDrainingAfterLimit(t *testing.T) {
	buffer := newBoundedBuffer(4)

	written, err := buffer.Write([]byte("abcdef"))

	if err != nil {
		t.Fatalf("Write returned an error and would stop draining: %v", err)
	}
	if written != 6 {
		t.Fatalf("Write consumed %d bytes, want 6", written)
	}
	if string(buffer.Bytes()) != "abcd" {
		t.Fatalf("buffered output = %q", buffer.Bytes())
	}
	if !buffer.exceeded {
		t.Fatal("buffer did not record the exceeded limit")
	}
}

func TestUploadArgumentsRejectRemoteShellSyntax(t *testing.T) {
	for _, destination := range []string{`C:\Blender Box\.setup.bin`, `C:\Blender&Box\.setup.bin`, `C:\Blender'Box\.setup.bin`} {
		if _, err := uploadArguments("windows-test", "/tmp/source", destination); err == nil {
			t.Fatalf("unsafe destination %q was accepted", destination)
		}
	}
	want := []string{"-q", "--", "/tmp/source", "windows-test:C:/Blender_Box/.setup-file.bin"}
	got, err := uploadArguments("windows-test", "/tmp/source", `C:\Blender_Box\.setup-file.bin`)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("upload arguments = %#v, error = %v", got, err)
	}
}
