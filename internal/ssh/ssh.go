package ssh

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

const (
	maxStdoutBytes = 1 << 20
	maxStderrBytes = 64 << 10
)

type Runner struct{}

func (Runner) Run(ctx context.Context, host string, remoteArgs []string, stdin []byte) ([]byte, error) {
	arguments := []string{
		"-o", "RequestTTY=no",
		"-o", "RemoteCommand=none",
		"--",
		host,
	}
	arguments = append(arguments, remoteArgs...)
	command := exec.CommandContext(ctx, "ssh", arguments...)
	command.Stdin = bytes.NewReader(stdin)
	stdout := newBoundedBuffer(maxStdoutBytes)
	stderr := newBoundedBuffer(maxStderrBytes)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if stdout.exceeded || stderr.exceeded {
			return nil, fmt.Errorf("SSH output exceeded its limit")
		}
		if message := stderr.String(); message != "" {
			return nil, fmt.Errorf("SSH failed: %s", message)
		}
		return nil, fmt.Errorf("SSH failed: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("SSH output exceeded its limit")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (buffer *boundedBuffer) Write(content []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return len(content), nil
	}
	if len(content) > remaining {
		_, _ = buffer.buffer.Write(content[:remaining])
		buffer.exceeded = true
		return len(content), nil
	}
	return buffer.buffer.Write(content)
}

func (buffer *boundedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func (buffer *boundedBuffer) String() string {
	return buffer.buffer.String()
}
