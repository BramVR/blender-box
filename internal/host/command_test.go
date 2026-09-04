package host

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestHostCapabilitiesCommandReturnsVersionedCaptureSupport(t *testing.T) {
	service := NewService(Dependencies{Daemon: &fakeDaemon{}, Desktop: &fakeDesktopCapturer{}})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := service.Run(
		context.Background(),
		[]string{"capabilities", "--state-root", t.TempDir()},
		strings.NewReader(`{"schema_version":1}`),
		&stdout,
		&stderr,
	)
	if exitCode != 0 || stderr.Len() != 0 {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var result CapabilitiesResponse
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 1 || result.Status != "pass" || len(result.Captures) != 3 {
		t.Fatalf("capabilities = %+v", result)
	}
}
