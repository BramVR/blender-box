package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/target"
)

func pairCommand(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Pairing client uses independently verified host-local offer and receipt digests.\n  pair prepare NAME --offer PATH --trust-offer SHA256 [--json]\n  pair complete NAME --receipt PATH --trust-receipt SHA256 [--json]\n  pair status NAME [--json]\nHost offer/enrollment/revoke and setup ssh are unsupported in this unit. Readiness requires a separate doctor command. Retain the request and credential while host enrollment is unconfirmed.")
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	operation := args[0]
	if operation == "offer" || operation == "enroll" || operation == "revoke" {
		return fail(stderr, "pair "+operation, fmt.Errorf("host enrollment and revocation are unsupported; no host changes performed"))
	}
	if operation != "prepare" && operation != "complete" && operation != "status" {
		return fail(stderr, "pair", fmt.Errorf("expected prepare, complete or status"))
	}
	if len(args) < 2 {
		fmt.Fprintln(stderr, "pair command requires NAME")
		return 2
	}
	name := args[1]
	flags := flag.NewFlagSet("pair "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print versioned JSON")
	var source, trust *string
	if operation == "prepare" {
		source = flags.String("offer", "", "host-local offer JSON")
		trust = flags.String("trust-offer", "", "exact offer digest verified through an independent trusted channel")
	}
	if operation == "complete" {
		source = flags.String("receipt", "", "host-local enrollment receipt JSON")
		trust = flags.String("trust-receipt", "", "exact receipt digest verified through an independent trusted channel")
	}
	if err := flags.Parse(args[2:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || operation != "status" && (*source == "" || *trust == "") {
		fmt.Fprintln(stderr, "pair requires its input file and independently verified trust digest")
		return 2
	}
	root, err := target.ConfigDir()
	if err != nil {
		return fail(stderr, "pair storage", err)
	}
	now := time.Now
	if dependencies.Now != nil {
		now = dependencies.Now
	}
	client := pairing.Client{Root: root, Now: now}
	if operation == "status" {
		view, err := client.Inspect(ctx, name)
		if err != nil {
			return fail(stderr, "pair status", err)
		}
		if *asJSON {
			return writeJSON(stdout, stderr, view)
		}
		fmt.Fprintf(stdout, "Pair %s: %s; readiness %s\n%s\n", view.PairID, view.Access, view.Readiness, view.Next)
		return 0
	}
	data, err := privatefile.ReadSource(*source, pairing.MaxDocumentSize)
	if err != nil {
		return fail(stderr, "pair input", err)
	}
	if operation == "prepare" {
		offer, err := pairing.TrustOffer(data, *trust, now())
		if err != nil {
			return fail(stderr, "trust offer", err)
		}
		intent, err := client.Prepare(ctx, name, offer)
		if err != nil {
			return fail(stderr, "prepare pair", err)
		}
		return writeJSON(stdout, stderr, intent)
	}
	receipt, err := pairing.TrustReceipt(data, *trust)
	if err != nil {
		return fail(stderr, "trust receipt", err)
	}
	selected, err := client.Complete(ctx, name, receipt)
	if err != nil {
		return fail(stderr, "complete pair", err)
	}
	if *asJSON {
		return writeJSON(stdout, stderr, struct {
			SchemaVersion int           `json:"schema_version"`
			Name          string        `json:"name"`
			Access        string        `json:"access"`
			Readiness     string        `json:"readiness"`
			Target        target.Target `json:"target"`
		}{1, name, "enrolled", "unchecked", selected})
	}
	fmt.Fprintf(stdout, "Target %s saved; access enrolled; readiness unchecked. Run doctor with the intended Scenario payload.\n", name)
	return 0
}
