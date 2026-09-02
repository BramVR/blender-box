package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/BramVR/blender-box/internal/cli"
	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/orchestrator"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/windows"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	sshRunner := sshtransport.Runner{}
	runtime := host.NewRuntime(host.ExecProcessRunner{})
	hostService := host.NewService(host.Dependencies{Tasks: runtime, Daemon: runtime})
	os.Exit(cli.Run(
		ctx,
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
		cli.Dependencies{
			SSH:    sshRunner,
			Runner: orchestrator.New(windows.NewAdapter(sshRunner)),
			Host:   hostService,
		},
	))
}
