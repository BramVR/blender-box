package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/BramVR/blender-box/internal/cli"
	"github.com/BramVR/blender-box/internal/host"
	linuxhost "github.com/BramVR/blender-box/internal/linux"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/pairing"
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
			SSH: sshRunner,
			Pairing: func(platform string) (pairing.Platform, error) {
				if platform == "windows" {
					return windowsinstall.NewPairingPlatform(), nil
				}
				return nil, fmt.Errorf("host pairing is unsupported on %s; no host changes performed", platform)
			},
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
