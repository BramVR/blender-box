package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/BramVR/blender-box/internal/cli"
	"github.com/BramVR/blender-box/internal/host"
	linuxhost "github.com/BramVR/blender-box/internal/linux"
	"github.com/BramVR/blender-box/internal/orchestrator"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windows"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	sshRunner := sshtransport.Runner{}
	configRoot, _ := target.ConfigDir()
	runtime := host.NewRuntime(host.ExecProcessRunner{})
	hostService := host.NewService(host.Dependencies{Tasks: runtime, Daemon: runtime})
	os.Exit(cli.Run(
		ctx,
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
		cli.Dependencies{
			SSH: sshRunner,
			RunnerFor: func(selected target.Target) cli.RunService {
				if selected.Platform() == "linux" {
					return orchestrator.New(linuxhost.NewAdapter(sshRunner), configRoot)
				}
				return orchestrator.New(windows.NewAdapter(sshRunner), configRoot)
			},
			Host: hostService,
		},
	))
}
