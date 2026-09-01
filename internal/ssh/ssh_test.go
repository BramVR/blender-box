package ssh

import "testing"

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
