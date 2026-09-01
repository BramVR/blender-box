package windows

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/target"
)

type checkSSH struct {
	output      string
	hadDeadline bool
}

func (fake *checkSSH) Run(ctx context.Context, _ string, _ []string, _ []byte) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	fake.hadDeadline = ok && time.Until(deadline) > 0 && time.Until(deadline) <= time.Minute
	return []byte(fake.output), nil
}

func TestCheckRejectsMalformedOrContradictoryEvidence(t *testing.T) {
	validChecks := `[
{"id":"host.windows","passed":true,"required":true},
{"id":"host.console-user","passed":true,"required":true},
{"id":"blender.executable","passed":true,"required":true},
{"id":"daemon.executable","passed":true,"required":true},
{"id":"host.executable","passed":true,"required":true},
{"id":"work-root.access","passed":true,"required":true},
{"id":"task.interactive","passed":true,"required":true}
]`
	cases := map[string]string{
		"null":                `{"schema_version":1,"status":"pass","checks":null}`,
		"empty array":         `{"schema_version":1,"status":"pass","checks":[]}`,
		"object":              `{"schema_version":1,"status":"pass","checks":{}}`,
		"missing required ID": `{"schema_version":1,"status":"pass","checks":[{"id":"host.windows","passed":true,"required":true}]}`,
		"duplicate ID":        `{"schema_version":1,"status":"pass","checks":[{"id":"host.windows","passed":true,"required":true},{"id":"host.windows","passed":true,"required":true}]}`,
		"pass with failed check": `{"schema_version":1,"status":"pass","checks":[
{"id":"host.windows","passed":false,"required":true},
{"id":"host.console-user","passed":true,"required":true},
{"id":"blender.executable","passed":true,"required":true},
{"id":"daemon.executable","passed":true,"required":true},
{"id":"host.executable","passed":true,"required":true},
{"id":"work-root.access","passed":true,"required":true},
{"id":"task.interactive","passed":true,"required":true}]}`,
		"fail without failure": `{"schema_version":1,"status":"fail","checks":` + validChecks + `}`,
	}

	for name, output := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Check(context.Background(), &checkSSH{output: output}, target.Target{})
			if err == nil || !strings.Contains(err.Error(), "invalid contract") {
				t.Fatalf("Check() error = %v, want invalid contract", err)
			}
		})
	}
}

func TestCheckAcceptsCompleteFailedEvidence(t *testing.T) {
	output := `{"schema_version":1,"status":"fail","checks":[
{"id":"host.windows","passed":true,"required":true},
{"id":"host.console-user","passed":true,"required":true},
{"id":"blender.executable","passed":false,"required":true},
{"id":"daemon.executable","passed":false,"required":true},
{"id":"host.executable","passed":false,"required":true},
{"id":"work-root.access","passed":false,"required":true},
{"id":"task.interactive","passed":false,"required":true}]}`

	fake := &checkSSH{output: output}
	result, err := Check(context.Background(), fake, target.Target{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "fail" || len(result.Checks) != 7 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !fake.hadDeadline {
		t.Fatal("Windows check called SSH without a bounded deadline")
	}
}
