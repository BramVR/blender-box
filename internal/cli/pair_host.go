package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
)

// pairHostCommand serves the host-local verbs: pair offer|enroll|revoke|status --state-root PATH.
func pairHostCommand(ctx context.Context, operation string, args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("pair "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("state-root", "", "absolute host-local shared authority root")
	asJSON := flags.Bool("json", false, "print versioned JSON")
	var installation, address, intentPath, trust, out, pairID *string
	var expires *time.Duration
	var apply *bool
	switch operation {
	case "offer":
		installation = flags.String("installation", "", "installed installation ID")
		address = flags.String("address", "", "hostname or IP the client will connect to")
		expires = flags.Duration("expires", 30*time.Minute, "offer validity from now (max 24h)")
		out = flags.String("out", "", "new file for the offer JSON")
	case "enroll":
		intentPath = flags.String("intent", "", "client enrollment request JSON")
		trust = flags.String("trust-intent", "", "exact request digest verified through an independent trusted channel")
		apply = flags.Bool("apply", false, "admit the key into the account's authorized keys file")
		out = flags.String("out", "", "new file for the enrollment receipt JSON (with --apply)")
	case "revoke":
		pairID = flags.String("pair", "", "exact pair ID from enroll or status")
		apply = flags.Bool("apply", false, "remove the pairing line")
	case "status":
		pairID = flags.String("pair", "", "limit to one pair ID")
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	missing := flags.NArg() != 0 || *root == ""
	switch operation {
	case "offer":
		missing = missing || *installation == "" || *address == "" || *out == ""
	case "enroll":
		missing = missing || *intentPath == "" || *trust == "" || *apply && *out == ""
	case "revoke":
		missing = missing || *pairID == ""
	}
	if missing {
		fmt.Fprintln(stderr, "pair "+operation+" requires --state-root and its inputs; enroll --apply requires --out")
		return 2
	}
	if !filepath.IsAbs(*root) || filepath.Clean(*root) != *root {
		return fail(stderr, "state root", fmt.Errorf("must be an absolute clean path"))
	}
	if dependencies.Pairing == nil {
		return fail(stderr, "pair "+operation, fmt.Errorf("host pairing is unsupported; no host changes performed"))
	}
	platform, err := dependencies.Pairing(runtime.GOOS)
	if err != nil {
		return fail(stderr, "pair "+operation, err)
	}
	now := time.Now
	if dependencies.Now != nil {
		now = dependencies.Now
	}
	h := pairing.Host{Root: *root, Platform: platform, Now: now}
	switch operation {
	case "offer":
		offer, sha, err := h.Offer(ctx, *installation, *address, *expires)
		if err != nil {
			return fail(stderr, "pair offer", err)
		}
		path, err := publishOut(*out, offer)
		if err != nil {
			return fail(stderr, "offer output", err)
		}
		if *asJSON {
			return writeJSON(stdout, stderr, struct {
				SchemaVersion int    `json:"schema_version"`
				OfferSHA256   string `json:"offer_sha256"`
				Path          string `json:"path"`
			}{1, sha, path})
		}
		fmt.Fprintf(stdout, "Offer written to %s\nOffer SHA-256 %s\nGive the client operator the file and read the digest through a trusted channel; the client verifies it with pair prepare --trust-offer.\n", path, sha)
		return 0
	case "enroll":
		data, err := privatefile.ReadSource(*intentPath, pairing.MaxDocumentSize)
		if err != nil {
			return fail(stderr, "pair input", err)
		}
		intent, err := pairing.TrustIntent(data, *trust)
		if err != nil {
			return fail(stderr, "trust request", err)
		}
		result, err := h.Enroll(ctx, intent, *apply)
		if err != nil {
			return fail(stderr, "pair enroll", err)
		}
		var path string
		if *apply {
			if path, err = publishOut(*out, result.Receipt); err != nil {
				return fail(stderr, "receipt output", err)
			}
		}
		if *asJSON {
			return writeJSON(stdout, stderr, result)
		}
		fmt.Fprintf(stdout, "Pair %s: %s\nAccount %s; keys file %s\n", result.PairID, result.State, result.Login, result.KeysFile)
		if result.SharedKeysFile {
			fmt.Fprintln(stdout, "This keys file is shared by every Administrators account on the host.")
		}
		fmt.Fprintf(stdout, "Line %s\nClient key %s\nKeys file SHA-256 before %s\n", result.Line, result.Fingerprint, result.KeysSHA256Before)
		if !*apply {
			fmt.Fprintln(stdout, "Preview only; repeat with --apply --out PATH to admit this key.")
			return 0
		}
		fmt.Fprintf(stdout, "Keys file SHA-256 after %s\nReceipt written to %s\nReceipt SHA-256 %s\nRead the receipt digest to the client operator; the client verifies it with pair complete --trust-receipt.\n", result.KeysSHA256After, path, result.ReceiptSHA)
		return 0
	case "revoke":
		result, err := h.Revoke(ctx, *pairID, "", "host-local", *apply)
		if err != nil {
			return fail(stderr, "pair revoke", err)
		}
		if *asJSON {
			return writeJSON(stdout, stderr, result)
		}
		fmt.Fprintf(stdout, "Pair %s: %s\nKeys file SHA-256 before %s\n", result.PairID, result.State, result.KeysSHA256Before)
		if !*apply {
			fmt.Fprintln(stdout, "Preview only; repeat with --apply to remove the pairing line.")
			return 0
		}
		fmt.Fprintf(stdout, "Keys file SHA-256 after %s\nExisting SSH sessions are not terminated; new authentication with this key is rejected.\n", result.KeysSHA256After)
		return 0
	}
	views, err := h.Status(ctx, *pairID)
	if err != nil {
		return fail(stderr, "pair status", err)
	}
	if *asJSON {
		return writeJSON(stdout, stderr, views)
	}
	if len(views) == 0 {
		fmt.Fprintln(stdout, "No pairings granted.")
	}
	for _, view := range views {
		fmt.Fprintf(stdout, "Pair %s: %s; account %s; keys file %s; client key %s\n", view.PairID, view.State, view.Login, view.KeysFile, view.Fingerprint)
	}
	return 0
}

// publishOut writes a create-only output file for the client operator; identical bytes already
// present count as written, so a repeated command with the same --out succeeds.
func publishOut(path string, data []byte) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := privatefile.ReadSource(absolute, pairing.MaxDocumentSize)
		if readErr != nil {
			return "", readErr
		}
		if string(existing) != string(data) {
			return "", fmt.Errorf("%s exists with different contents", absolute)
		}
		return absolute, nil
	}
	if err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}
	return absolute, file.Close()
}

// hostPairRevoke is the stdin-JSON machine command a paired key runs over SSH to revoke itself.
func hostPairRevoke(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("host pair-revoke", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("state-root", "", "absolute host-local shared authority root")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*root) || filepath.Clean(*root) != *root {
		fmt.Fprintln(stderr, "host pair-revoke requires --state-root PATH")
		return 2
	}
	data, err := io.ReadAll(io.LimitReader(stdin, pairing.MaxDocumentSize+1))
	if err != nil || len(data) > pairing.MaxDocumentSize {
		return fail(stderr, "host pair-revoke", fmt.Errorf("request must be bounded JSON"))
	}
	var request pairing.RevokeRequest
	if err := strictjson.Decode(data, &request); err != nil {
		return fail(stderr, "host pair-revoke", err)
	}
	if err := request.Validate(); err != nil {
		return fail(stderr, "host pair-revoke", err)
	}
	if dependencies.Pairing == nil {
		return fail(stderr, "host pair-revoke", fmt.Errorf("host pairing is unsupported; no host changes performed"))
	}
	platform, err := dependencies.Pairing(runtime.GOOS)
	if err != nil {
		return fail(stderr, "host pair-revoke", err)
	}
	now := time.Now
	if dependencies.Now != nil {
		now = dependencies.Now
	}
	result, err := (pairing.Host{Root: *root, Platform: platform, Now: now}).Revoke(ctx, request.PairID, request.ClientPublicKeyHash, "paired-ssh", true)
	if err != nil {
		return fail(stderr, "host pair-revoke", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return fail(stderr, "host pair-revoke", err)
	}
	fmt.Fprintln(stdout, strings.TrimSpace(string(encoded)))
	return 0
}
