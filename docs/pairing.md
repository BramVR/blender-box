---
summary: Pair a developer machine with an installed Windows host, run a first Scenario, troubleshoot connections, and revoke access.
read_when:
  - Pairing a client with an installed Windows host.
  - Diagnosing a failed paired connection or doctor check.
  - Revoking or forgetting a pairing.
---

# Pair a client with a Windows host

Use this guide when you operate an owned Windows host and want a developer machine to run Scenarios on it. The operator runs host commands on Windows. The developer runs client commands on the client machine. One person can play both roles. Pairing adds exactly one marked `restrict` key line to the account's effective `AuthorizedKeysFile` and preserves every other line. It never edits `sshd_config`, `known_hosts`, your SSH config, or your SSH agent. The Blender MCP add-on stays on host loopback and is never forwarded. Each exchange prints a SHA-256 digest. Pass the digest to the other side through an independent trusted channel, such as reading it aloud or a chat you already trust. Never take a digest from the JSON file itself.

## Prerequisites

- A host installed with the [Windows installation guide](windows-installation.md). Keep its state root and installation ID.
- The same Windows account for SSH and for the logged-in interactive desktop.
- An elevated PowerShell on the host, or your existing trusted administrator SSH channel. Host commands refuse without elevation.
- A POSIX client, such as macOS or Linux, with `ssh` and `ssh-keygen` on `PATH`. Windows clients refuse paired credentials until native owner and ACL checks exist.

Tailscale is optional. Any SSH route from the client to the host address works, such as a LAN, another VPN, or a Tailscale name like `win-box.example.ts.net`. Existing SSH alias targets stay valid and need no pairing.

The examples use the state root `C:\BlenderBox` and the target name `studio`. Replace the uppercase placeholders with the values your commands print.

## Pair and run a first Scenario

1. On the host, preview SSH preparation.

   ```powershell
   blender-box setup ssh --platform windows --state-root C:\BlenderBox --installation INSTALLATION_ID
   ```

   The preview prints a Plan SHA-256. A stock host with sshd running and an inbound rule for its port prints `No changes needed`. Skip to step 2 in that case. Otherwise the plan contains only what is missing. It can start sshd, set sshd to start automatically, and add one inbound firewall rule for `sshd.exe`. A new rule needs `--remote-address CIDR,...`. Use `--firewall-profile` to choose its profiles. The default is `Domain,Private`. Setup refuses when sshd resolves `pubkeyauthentication no`.

2. Apply the reviewed plan.

   ```powershell
   blender-box setup ssh --platform windows --state-root C:\BlenderBox --installation INSTALLATION_ID --apply --expected-plan PLAN_SHA256
   ```

   To undo it later, preview and apply the same command with `--remove`. Removal restores the prior sshd start type only while the current start type is still the one setup set. It deletes only its own rule, and only when the rule name and definition match. It never stops sshd, because that would end your own session.

3. On the host, issue an offer.

   ```powershell
   blender-box pair offer --state-root C:\BlenderBox --installation INSTALLATION_ID --address win-box.example.ts.net --out offer.json
   ```

   Expected output:

   ```
   Offer SHA-256 OFFER_SHA256
   ```

   `--address` is the host name or IP address that the client connects to. The offer expires after 30 minutes. Use `--expires` to change that, up to 24 hours. Copy `offer.json` to the client by any means. Read the digest to the developer through the trusted channel.

4. On the client, prepare the pairing.

   ```sh
   blender-box pair prepare studio --offer offer.json --trust-offer OFFER_SHA256 > intent.json
   ```

   Preparation verifies the offer, creates a dedicated Ed25519 key, and writes the public enrollment request to stdout. The private key stays on the client. Standard error names the request digest:

   ```
   Enrollment request SHA-256 INTENT_SHA256
   ```

   Copy `intent.json` to the host. Read the digest to the operator through the trusted channel.

5. On the host, preview the enrollment.

   ```powershell
   blender-box pair enroll --state-root C:\BlenderBox --intent intent.json --trust-intent INTENT_SHA256
   ```

   The preview shows the account, the keys file, the exact `restrict` line, and the OpenSSH `SHA256:` fingerprint of the client key. For an administrator account, the keys file is the shared `administrators_authorized_keys`, and the preview says so. Every administrator on the host authenticates through that file. Enrollment refuses an expired offer, an offer this host did not issue, and a host identity that changed since the offer.

6. Apply the enrollment.

   ```powershell
   blender-box pair enroll --state-root C:\BlenderBox --intent intent.json --trust-intent INTENT_SHA256 --apply --out receipt.json
   ```

   Expected output:

   ```
   Receipt SHA-256 RECEIPT_SHA256
   ```

   Copy `receipt.json` to the client. Read the digest to the developer through the trusted channel.

7. On the client, complete the pairing.

   ```sh
   blender-box pair complete studio --receipt receipt.json --trust-receipt RECEIPT_SHA256
   ```

   Expected output:

   ```
   Target studio saved; access enrolled; readiness unchecked. Run doctor with the intended Scenario payload.
   ```

   Completion never replaces an existing target with the same name.

8. Check readiness with the Scenario you intend to run. See [Create a Run Payload](../README.md#create-a-run-payload) for the payload format.

   ```sh
   blender-box doctor --target-name studio --payload scenario.json
   ```

   Expected output is `Doctor: pass`. If doctor fails, it prints one line per problem. See [Troubleshoot connections](#troubleshoot-connections).

9. Start the first Run.

   ```sh
   blender-box run --target-name studio --payload scenario.json
   ```

### Repeat a step after an interruption

Every step is safe to repeat with the same inputs. An interrupted `pair prepare` or `pair complete` keeps its request and key, so run the same command again. Repeating `pair enroll --apply` with the same request returns a byte-identical receipt with the same digest. `pair complete` still accepts that receipt after the offer expires, because the host may already have applied the request. A new preparation needs an unexpired offer. Interrupting the client never revokes host access.

## Check the pairing state

Run `blender-box pair status studio` on the client. It prints the Pair ID, the access state, and the next step. Readiness always reads `unchecked` here, because only `doctor` checks readiness. The access states are:

- `none`. No local pairing state exists. Prepare a pairing from a trusted offer.
- `preparation-pending`. Preparation stopped before it finished. Repeat `pair prepare` with the original offer.
- `prepared-unconfirmed`. The request exists, but the client has no accepted receipt. Keep the request and key, and complete with the trusted receipt.
- `enrolled-publication-pending`. The client accepted the receipt but has not saved the target. Repeat `pair complete` with the original receipt.
- `enrolled`. The saved target matches the receipt. Run `doctor`.
- `conflict`. The client key is missing or changed, or a different target already uses the name. Preserve the pairing state and follow the printed next step.
- `revocation-pending`. The host revoked or already rejects the key, but the client has not proven a fresh connection is rejected. Repeat `pair revoke`.
- `forget-pending`. Local cleanup started but stopped before it finished. Repeat `pair forget`.

## Troubleshoot connections

`doctor` prints one line per problem in the form `CLASS (CHECK): MESSAGE Next: NEXT_STEP`. `doctor --json` carries the same problems under `host.problems`, each with `class`, `check`, `message`, and `next`. `run` checks the host before it acquires the Host Lock. If a check fails, `run` refuses with the list of classes and tells you to run `doctor`.

Connection failures use the check `ssh.connection`:

- `host-unreachable`. The connection was refused or timed out, had no route, or the name did not resolve. Check that the host is on and sshd is running. Check that the client can reach the host address and port.
- `tailscale-unreachable`. The host is unreachable and its address is a Tailscale address in `100.64.0.0/10` or `fd7a:115c:a1e0::/48`, or a `*.ts.net` name. Connect the client to the tailnet, check `tailscale status`, and check that the host is online there.
- `host-key-mismatch`. The host presented a key that differs from the pinned host key. Do not replace trust. Verify the host on its console, then pair again from a new offer.
- `auth-rejected`. SSH authentication failed because the host refused the client key. Check the pairing on the host with `pair status --state-root`, or pair again. A `Match Address` or `Match Host` block in `sshd_config` that sends this client to other settings also fails as `auth-rejected`.

Host readiness failures come from the host checks:

- `runtime-incompatible`. The Blender, daemon, or host executable check failed. On the host, run `blender-box setup inspect --platform windows --state-root C:\BlenderBox` and reinstall the runtime it reports.
- `interactive-desktop-unavailable`. The target's interactive user is not signed in to the host desktop. Sign in as that user and leave the session signed in.
- `account-mismatch`. The SSH account differs from the account that owns the interactive desktop. Connect as the desktop account, then pair or import that target again.
- `setup-incomplete`. Another required check failed. On the host, run `setup inspect` and apply the reviewed plan.

## Revoke or forget a pairing

Three commands remove a pairing at different depths. Only `pair revoke` removes host access.

### Revoke access from the client

```sh
blender-box pair revoke studio
```

`pair revoke` asks the host to remove exactly the line of this pairing, and it authenticates with the paired key itself. Next, it opens a fresh paired connection and requires the host to reject it. Only after that rejection does it remove local state. The outcome is one of these states:

- `revoked`. The host removed its line and rejects a fresh connection. Local pairing state is gone.
- `host-revoked-unconfirmed`. The host reported removal, but no fresh connection was proven rejected. Local state stays. If the key still authenticates, look on the host for another authorized copy of the key. Then repeat `pair revoke`. The retry repeats only the rejection check.
- `unconfirmed`. The host did not confirm removal. The JSON `failure` field names the connection class when there is one. Every local file stays. Retry when the host is reachable, or revoke on the host as described below.

If the host already rejects the key, `pair revoke` still converges. This happens when a lost response hid an earlier removal. The command records that the host returned no revocation result, proves a fresh connection is rejected, and removes local state. It then tells you to confirm with the host `pair status` command.

The host refuses revocation while a Run is active or unresolved on it. Finish or recover that Run first. `--timeout` bounds the whole command. The default is 2 minutes. `--json` prints the outcome with `state`, `host`, `failure`, and `next`. A pairing without an accepted receipt has no host access to revoke, so `pair revoke` tells you to run `pair forget`.

### Revoke on the host when the client is lost

Find the Pair ID, preview the removal, then apply it:

```powershell
blender-box pair status --state-root C:\BlenderBox
blender-box pair revoke --state-root C:\BlenderBox --pair PAIR_ID
blender-box pair revoke --state-root C:\BlenderBox --pair PAIR_ID --apply
```

Host revocation removes only the exact line of that Pair ID. If the client machine comes back, run `pair revoke studio` there. The host already rejects the key, so the command converges and removes local state.

### Forget local state only

```sh
blender-box pair forget studio
```

`pair forget` never contacts the host. It removes the saved target when that target matches the receipt, then the receipt, the key, the request, and the other pairing records. It refuses while the host has accepted access that is not confirmed revoked. To forget anyway, pass `--keep-remote-access`. The output then says `Remote access NOT revoked` and prints the host command that removes the key. If the host never confirmed enrollment, `pair forget` proceeds and prints the host `pair status` command. Use that command to check whether the host applied the request.

### Forget only the saved target

```sh
blender-box targets forget studio
```

`targets forget` removes only the saved profile. For a paired target, it prints a warning:

```
Remote access NOT revoked (pair PAIR_ID). Run: blender-box pair revoke studio
```

The pairing records and key stay, so `pair revoke studio` still works afterwards.
