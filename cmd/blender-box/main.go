package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/BramVR/blender-box/internal/cli"
	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/orchestrator"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windows"
	"github.com/BramVR/blender-box/internal/windowsinstall"
)

func main() {
	if handled, code := windowsinstall.RunInternal(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	sshRunner := sshtransport.Runner{}
	configRoot, _ := target.ConfigDir()
	runtime := host.NewRuntime(host.ExecProcessRunner{})
	hostService := host.NewService(host.Dependencies{Tasks: runtime, Daemon: runtime, Desktop: runtime, UIActor: runtime})
	os.Exit(cli.Run(
		ctx,
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
		cli.Dependencies{
			SSH:    sshRunner,
			Runner: orchestrator.New(windows.NewAdapter(sshRunner), configRoot),
			Host:   hostService,
		},
	))
}
