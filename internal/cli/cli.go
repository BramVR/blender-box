package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windows"
)

type Dependencies struct {
	SSH windows.SSH
}

func Run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, dependencies Dependencies) int {
	if len(args) < 2 || args[0] != "windows" || args[1] != "check" {
		fmt.Fprintln(stderr, "usage: blender-box windows check --target PATH [--json]")
		return 2
	}
	flags := flag.NewFlagSet("windows check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	targetPath := flags.String("target", "", "path to target JSON")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	if err := flags.Parse(args[2:]); err != nil {
		return 2
	}
	if *targetPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "windows check requires --target PATH")
		return 2
	}
	selected, err := target.Load(*targetPath)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: %v\n", err)
		return 1
	}
	if dependencies.SSH == nil {
		fmt.Fprintln(stderr, "ERROR: SSH transport is unavailable")
		return 1
	}
	result, err := windows.Check(ctx, dependencies.SSH, selected)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: %v\n", err)
		return 1
	}
	if *asJSON {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: encode check result: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(encoded))
	} else {
		fmt.Fprintf(stdout, "Windows check: %s\n", result.Status)
	}
	if result.Status != "pass" {
		return 1
	}
	return 0
}
