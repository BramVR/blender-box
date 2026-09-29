---
summary: Prepare Windows OpenSSH for pairing, then issue offers, enroll one client key, and revoke it, all from the host.
read_when:
  - Pairing a client with an installed Windows host.
  - Diagnosing a refused enrollment or revocation on the host.
---

# Prepare SSH and pair a client on Windows

Use this guide as the operator of an owned Windows host that already has an installed runtime ([Install Blender Box on Windows](windows-installation.md)). Run every command in an elevated PowerShell on the host, or over an existing admin SSH session. The commands refuse without elevation.

Safety boundary: these commands never edit `sshd_config`, never restart sshd, never delete anything by name pattern, and change only the sshd service start state, one owned firewall rule, one line in the authorized keys file sshd resolves for the account, and records under the state root. Preview is the default; every change needs `--apply`.

The variables below name operator-verified values. `$Bootstrap` is the verified host executable, `$StateRoot` the installed state root, and `$InstallationID` the `bbxi_...` id from the installation receipt.

## Check sshd and open its port

Preview first:

```powershell
& $Bootstrap setup ssh --platform windows --state-root $StateRoot --installation $InstallationID --remote-address 100.64.0.0/10
```

The preview reports the account, the sshd port, the service state, and the plan: start sshd if it is stopped, set its start type to Automatic if it is not, and create one inbound rule `BlenderBox-SSH-<installation>` only when no enabled inbound rule already admits the port. `--remote-address` limits that rule to the client prefixes you name and is required only when a rule is planned. `--firewall-profile` defaults to `Domain,Private`.

A stock host with sshd running, Automatic, and the stock `OpenSSH-Server-In-TCP` rule reports `unchanged`. Nothing is written and no receipt exists.

If the preview reports `pubkey-authentication-disabled`, enable `PubkeyAuthentication` in `sshd_config` yourself. The command does not edit that file.

To apply, repeat with the plan digest from the preview:

```powershell
& $Bootstrap setup ssh --platform windows --state-root $StateRoot --installation $InstallationID --remote-address 100.64.0.0/10 --apply --expected-plan $PlanSHA256
```

Apply records the prior start type and the rule in `$StateRoot\ssh-preparation\<installation>.json`. A retry converges.

To reverse it later:

```powershell
& $Bootstrap setup ssh --platform windows --state-root $StateRoot --installation $InstallationID --remove
& $Bootstrap setup ssh --platform windows --state-root $StateRoot --installation $InstallationID --remove --apply
```

Removal restores the prior start type only when the current type is still the one it set, deletes the rule only when its name and definition still match, and never stops sshd, because that would cut your own session.

## Issue an offer

```powershell
& $Bootstrap pair offer --state-root $StateRoot --installation $InstallationID --address $HostAddress --out offer.json
```

`$HostAddress` is the hostname or IP the client will connect to, for example the Tailscale name. The command resolves the sshd port, the Ed25519 host key, the account, and the keys file, then writes the offer and prints `Offer SHA-256`. Offers expire after 30 minutes by default (`--expires`, at most 24h).

Send the file to the client operator and read the digest to them through a channel you trust, such as a call. The client verifies the digest with `pair prepare NAME --offer offer.json --trust-offer <digest>` and sends back the enrollment request JSON and its digest.

## Enroll the client key

Preview:

```powershell
& $Bootstrap pair enroll --state-root $StateRoot --intent intent.json --trust-intent $IntentSHA256
```

The preview shows the account, the keys file, the exact line to add, the client key fingerprint, and the current keys-file hash. When the keys file is `administrators_authorized_keys`, the output says the file is shared: the key authenticates as any Administrators account on this host. The paired target pins the login user, and readiness proves the SSH account is the interactive account.

The preview refuses without writing when the offer is unknown or expired, when the host identity, root identity, or host key changed since the offer, when the same key already exists on another line, or when this pair id already names a different key.

Apply:

```powershell
& $Bootstrap pair enroll --state-root $StateRoot --intent intent.json --trust-intent $IntentSHA256 --apply --out receipt.json
```

Apply records the grant, appends the line `restrict <key> blender-box-pair:<pair id>`, verifies it, and writes the receipt. It prints the keys-file hash before and after and `Receipt SHA-256`. Read that digest to the client operator; they finish with `pair complete NAME --receipt receipt.json --trust-receipt <digest>`.

Repeating apply is safe. It returns the same receipt bytes and does not add a second line. An interrupted apply leaves the pair in `granting`; run the same command again.

## Inspect pairings

```powershell
& $Bootstrap pair status --state-root $StateRoot
& $Bootstrap pair status --state-root $StateRoot --pair $PairID --json
```

States: `granting` (grant recorded, line not yet present), `granted`, `revoking` (revocation recorded, line still present), `revoked`, and `conflict` (the line appears more than once; fix the file by hand).

## Revoke a pairing

```powershell
& $Bootstrap pair revoke --state-root $StateRoot --pair $PairID
& $Bootstrap pair revoke --state-root $StateRoot --pair $PairID --apply
```

Revoke records a tombstone, removes exactly that pairing's line, and verifies it is gone. Every other line keeps its bytes. It refuses while a Run is active or unresolved (`host-lock.json`, a pending request, a Run root, or an unresolved receipt) so a revoke never races a Run. A revoked pair id cannot be enrolled again; prepare a new pairing instead.

Revocation stops new authentication with that key. It does not terminate SSH sessions that are already open.

The client can also revoke its own pairing over SSH with `pair revoke NAME`, which runs `host pair-revoke` on this host with the pair's own key fingerprint and then proves a fresh connection is rejected.

## What the commands leave behind

- `$StateRoot\pairings\offers\<sha>.json`, `grants\<pair id>.json`, `tombstones\<pair id>.json`: create-only records. Keep them.
- `$StateRoot\ssh-preparation\<installation>.json`: the preparation receipt, present only after an apply.
- A `.blender-box-*.tmp` file beside the keys file after an abrupt exit. It grants nothing; delete it yourself after checking its contents.
