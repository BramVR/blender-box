package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/windowsinstall"
)

func setupSSHCommand(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	for _, arg := range args {
		if arg == "--apply" || arg == "-apply" || len(arg) > 8 && arg[:8] == "--apply=" {
			return fail(stderr, "setup ssh", fmt.Errorf("SSH apply is unsupported; preview creates no authority"))
		}
	}
	flags := flag.NewFlagSet("setup ssh", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("request", "", "bounded explicit SSH preparation request JSON; preview only")
	asJSON := flags.Bool("json", false, "print exact preview plan or typed refusal")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *path == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "setup ssh requires --request PATH; preview only, apply is unsupported")
		return 2
	}
	data, err := privatefile.ReadSource(*path, 64<<10)
	if err != nil {
		return fail(stderr, "setup ssh request", err)
	}
	var request windowsinstall.SSHPreparationRequest
	if !utf8.Valid(data) {
		return fail(stderr, "setup ssh request", fmt.Errorf("invalid UTF-8"))
	}
	if err := strictjson.Decode(data, &request); err != nil {
		return fail(stderr, "setup ssh request", err)
	}
	preview := dependencies.PreviewSSH
	if preview == nil {
		preview = windowsinstall.PreviewSSH
	}
	result, err := preview(ctx, request)
	if *asJSON {
		if code := writeJSON(stdout, stderr, result); code != 0 {
			return code
		}
	} else {
		fmt.Fprintf(stdout, "SSH preparation %s. Preview creates no host state or authority.\n", result.State)
		if result.Plan != nil {
			fmt.Fprintf(stdout, "Plan SHA-256 %s\n", result.Plan.PlanSHA256)
		}
		for _, problem := range result.Problems {
			fmt.Fprintf(stdout, "%s: %s\n", problem.Code, problem.Message)
		}
	}
	if err != nil {
		return fail(stderr, "setup ssh", err)
	}
	if result.State != "previewed" {
		return 1
	}
	return 0
}
