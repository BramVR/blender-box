package host

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/BramVR/blender-box/internal/orchestrator"
)

const maxHostInput = 48 << 20

func (service *Service) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: blender-box host COMMAND --state-root PATH")
		return 2
	}
	operation := args[0]
	flags := flag.NewFlagSet("host "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("state-root", "", "operator-managed state root")
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *root == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "host command requires --state-root PATH")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "ERROR: host %s: %v\n", operation, err)
		return 1
	}
	write := func(value any) int {
		if err := json.NewEncoder(stdout).Encode(value); err != nil {
			return fail(err)
		}
		return 0
	}

	switch operation {
	case "capabilities":
		var request CapabilitiesRequest
		if err := decodeJSONReader(stdin, &request, maxScenarioJSON); err != nil {
			return fail(err)
		}
		result, err := service.Capabilities(ctx, request)
		if err != nil {
			return fail(err)
		}
		return write(result)
	case "acquire":
		var request AcquireRequest
		if err := decodeJSONReader(stdin, &request, maxScenarioJSON); err != nil {
			return fail(err)
		}
		if err := service.Acquire(ctx, *root, request); err != nil {
			return fail(err)
		}
		return write(Acknowledgement{SchemaVersion: 1, Status: "acquired"})
	case "stage":
		var request StageRequest
		if err := decodeJSONReader(stdin, &request, maxHostInput); err != nil {
			return fail(err)
		}
		if err := service.Stage(ctx, *root, request); err != nil {
			return fail(err)
		}
		return write(Acknowledgement{SchemaVersion: 1, Status: "staged"})
	case "start":
		var request orchestrator.RunRequest
		if err := decodeJSONReader(stdin, &request, maxScenarioJSON); err != nil {
			return fail(err)
		}
		receipt, err := service.Start(ctx, *root, request)
		if err != nil {
			return fail(err)
		}
		return write(receipt)
	case "status":
		var request StatusRequest
		if err := decodeJSONReader(stdin, &request, maxScenarioJSON); err != nil {
			return fail(err)
		}
		receipt, err := service.Status(*root, request)
		if err != nil {
			return fail(err)
		}
		return write(receipt)
	case "fetch":
		var request FetchRequest
		if err := decodeJSONReader(stdin, &request, maxScenarioJSON); err != nil {
			return fail(err)
		}
		contents, err := service.Fetch(*root, request)
		if err != nil {
			return fail(err)
		}
		return write(FetchResponse{SchemaVersion: 1, Contents: contents})
	case "settle":
		var request SettleRequest
		if err := decodeJSONReader(stdin, &request, maxScenarioJSON); err != nil {
			return fail(err)
		}
		cleanup, err := service.Settle(ctx, *root, request)
		if err != nil {
			return fail(err)
		}
		return write(SettleResponse{SchemaVersion: 1, Cleanup: cleanup})
	case "run-request":
		if err := service.ExecutePending(ctx, *root); err != nil {
			return fail(err)
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown host command %q\n", operation)
		return 2
	}
}

func decodeJSONReader(reader io.Reader, value any, limit int64) error {
	contents, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if int64(len(contents)) > limit {
		return fmt.Errorf("request exceeds input limit")
	}
	return decodeJSONBytes(contents, value, limit)
}
