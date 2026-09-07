package windowsinstall

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/BramVR/blender-box/internal/strictjson"
)

func decodeKeeperRequest(ctx context.Context, input io.Reader) (Request, error) {
	type read struct {
		data []byte
		err  error
	}
	done := make(chan read, 1)
	go func() { data, err := io.ReadAll(io.LimitReader(input, (64<<10)+1)); done <- read{data, err} }()
	select {
	case result := <-done:
		if result.err != nil {
			return Request{}, result.err
		}
		if len(result.data) > 64<<10 {
			return Request{}, fmt.Errorf("setup request exceeds input bound")
		}
		var request Request
		if err := strictjson.Decode(result.data, &request); err != nil {
			return Request{}, err
		}
		if err := validOperationRequest(request); err != nil {
			return Request{}, err
		}
		if !request.Apply || request.ExecutionToken != "" || request.Operation != "install" && request.Operation != "remove" {
			return Request{}, fmt.Errorf("invalid keeper operation")
		}
		return request, nil
	case <-ctx.Done():
		return Request{}, ctx.Err()
	}
}

// A stopped predecessor keeps its cancellation record; successor tokens use other directories.
func watchExecutionCancellation(ctx context.Context, record executionRequest) (context.Context, context.CancelFunc) {
	watching, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			var request executionCancel
			err := readExecutionJSON(filepath.Join(record.directory(), "cancel.json"), &request)
			if err == nil || !os.IsNotExist(err) {
				cancel()
				return
			}
			select {
			case <-watching.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return watching, cancel
}

func (o *owner) serveKeeper(ctx context.Context, input io.Reader) (Result, error) {
	request, err := decodeKeeperRequest(ctx, input)
	if err != nil {
		return Result{}, err
	}
	return o.keep(context.Background(), request)
}
