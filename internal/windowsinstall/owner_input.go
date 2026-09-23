package windowsinstall

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

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
