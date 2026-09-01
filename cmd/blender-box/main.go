package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/BramVR/blender-box/internal/cli"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(cli.Run(
		ctx,
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		cli.Dependencies{SSH: sshtransport.Runner{}},
	))
}
