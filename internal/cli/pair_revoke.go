package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/target"
)

func pairRevocationCommand(ctx context.Context, operation string, args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "pair %s requires NAME\n", operation)
		return 2
	}
	name := args[0]
	flags := flag.NewFlagSet("pair "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print versioned JSON")
	var timeout *time.Duration
	var keep *bool
	if operation == "revoke" {
		timeout = flags.Duration("timeout", 2*time.Minute, "host revocation and rejection check timeout")
	} else {
		keep = flags.Bool("keep-remote-access", false, "forget local state although the host may still accept this pairing's key")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || timeout != nil && *timeout <= 0 {
		fmt.Fprintf(stderr, "pair %s takes NAME and its flags only; --timeout must be positive\n", operation)
		return 2
	}
	root, err := target.ConfigDir()
	if err != nil {
		return fail(stderr, "pair storage", err)
	}
	client := pairing.Client{Root: root}
	if operation == "forget" {
		result, err := client.Forget(ctx, name, *keep)
		if err != nil {
			return fail(stderr, "pair forget", err)
		}
		if *asJSON {
			return writeJSON(stdout, stderr, result)
		}
		switch result.RemoteAccess {
		case "revoked":
			fmt.Fprintf(stdout, "Pairing %s forgotten locally; the host confirmed revocation of pair %s.\n", name, result.PairID)
		case "not-revoked":
			fmt.Fprintf(stdout, "Pairing %s forgotten locally. Remote access NOT revoked (pair %s).\nNext: %s\n", name, result.PairID, result.Next)
		case "unconfirmed":
			fmt.Fprintf(stdout, "Pairing %s forgotten locally; host enrollment of pair %s was never confirmed.\nNext: %s\n", name, result.PairID, result.Next)
		default:
			fmt.Fprintf(stdout, "Pairing %s forgotten locally.\n", name)
		}
		return 0
	}
	if dependencies.PairRemote == nil {
		return fail(stderr, "pair revoke", fmt.Errorf("pairing revocation transport is unavailable"))
	}
	requestCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	outcome, err := client.Revoke(requestCtx, name, dependencies.PairRemote)
	if outcome.State == "" {
		return fail(stderr, "pair revoke", err)
	}
	if *asJSON {
		if code := writeJSON(stdout, stderr, outcome); code != 0 {
			return code
		}
	} else {
		fmt.Fprintln(stdout, revokeSummary(outcome))
		if outcome.Next != "" {
			fmt.Fprintf(stdout, "Next: %s\n", outcome.Next)
		}
	}
	if err != nil {
		return fail(stderr, "pair revoke", err)
	}
	return 0
}

func revokeSummary(outcome pairing.RevokeOutcome) string {
	hostSaid := "the host removed its key"
	if outcome.Host == "already-rejected" {
		hostSaid = "the host returned no revocation result"
	}
	switch outcome.State {
	case pairing.Revoked:
		return fmt.Sprintf("Pair %s revoked: %s and a fresh paired connection is rejected. Local pairing state removed.", outcome.PairID, hostSaid)
	case pairing.HostRevokedUnconfirmed:
		return fmt.Sprintf("Pair %s: %s, but a fresh paired connection is not proven rejected. Local pairing state kept.", outcome.PairID, hostSaid)
	default:
		return fmt.Sprintf("Pair %s: revocation unconfirmed. Local pairing state kept.", outcome.PairID)
	}
}

func pairedForgetWarning(root, name string) string {
	view, err := (pairing.Client{Root: root}).Inspect(context.Background(), name)
	if err != nil || view.PairID == "" {
		return "Remote access NOT revoked; no local pairing record names this target. Remove its key on the host."
	}
	return fmt.Sprintf("Remote access NOT revoked (pair %s). Run: blender-box pair revoke %s", view.PairID, name)
}
