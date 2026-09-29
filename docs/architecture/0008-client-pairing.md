---
summary: Local pairing pins SSH identity and preserves approval and publication recovery separately from host readiness.
read_when:
  - Changing paired target schema, client credentials, pairing trust, or local reconciliation.
  - Changing host offers, grants, tombstones, the keys-file transaction, or `setup ssh`.
  - Extending the hosted pairing proof.
---

# Client pairing

## Decision

A paired target binds the direct endpoint, login, Ed25519 host public key and dedicated client-key fingerprint. Schema version 3 carries that connection alongside one existing Windows or Linux body. It uses the existing target store and original Run fingerprint. Alias schemas 1 and 2 retain their exact canonical bytes and fingerprints.

The client requires a separately trusted host offer and enrollment receipt. The host issues both from its own state root through elevated host-local commands, admits exactly one marked `restrict` line into the keys file its sshd resolves for the account, and removes exactly that line on revocation. No command turns local preparation into a readiness check; `doctor` does that.

## Local workflow

`pair prepare NAME --offer PATH --trust-offer SHA256` verifies an offer against a digest obtained through an independent trusted channel. A JSON file alone supplies no trust. The offer binds its expiry, bootstrap and installation identities, account and root identities, installed target, and exact server endpoint.

Preparation checks the complete retained record's size before creating credentials. It durably reserves the name, offer and request IDs, then retains one winning Ed25519 seed under that preparation. Concurrent callers use the same reservation and seed. The client derives the key in memory, retains the immutable enrollment intent, publishes the fingerprint-addressed credential, and exports only the public request. A repeated preparation returns the original intent after checking its key. A different offer or preexisting target name refuses.

The seed reproduces the original OpenSSH private key after an interrupted publication. New preparation paths validate durable credential bytes without temporary private-key copies outside pairing storage. An intent without its retained preparation refuses retry, completion and status. The unencrypted single-Ed25519 encoding follows [OpenSSH's key format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key); tests verify it with the real `ssh-keygen` reader.

`pair complete NAME --receipt PATH --trust-receipt SHA256` verifies the independent receipt digest, then matches the receipt against the retained Pair ID, operation, intent, public key and complete expected target. It retains the accepted receipt before saving the target. Saving uses `target.Store.Save`, the same publication path as import, without replacing an existing profile.

A lost response or interrupted publication leaves the original intent, key and accepted receipt available for retry. An unrelated replacement target remains untouched. Completion can reconcile a receipt after the original offer expires because the host may already have applied the request. Fresh preparation requires an unexpired offer. Interrupting the client does not revoke remote access or erase pending recovery material.

`pair status NAME` reports access and readiness separately. An interrupted preparation reports its retained Pair ID and directs you to repeat preparation with the original offer. `prepared-unconfirmed` means that the client has no accepted enrollment receipt. Accepted receipt state can still need target publication. A saved matching target reports enrolled access with unchecked readiness. The next operational step is `doctor` with the intended Scenario payload.

## Credential and transport boundary

Keys live under `credentials/<fingerprint>/id_ed25519` in the private user configuration root. The fingerprint is lowercase hexadecimal SHA-256 of the canonical SSH public-key wire bytes, not OpenSSH's display string. POSIX reads enforce current-user ownership, private permissions, bounded regular files, and a matching derived public key. Windows key operations refuse until native owner and ACL enforcement exists.

Retain the preparation and seed as private recovery material. Each globally published key has a durable intent naming it. An abrupt process exit can leave atomic-publication temporary copies beneath the original preparation or that intent's fingerprint directory. Those copies remain attributable to the pairing; their count is not bounded, and preparation does not sweep or delete credentials.

The shared transport accepts one `target.Connection`. Alias connections retain operator configuration. Paired SSH and SCP use the same generated private configuration and verified key copy. Host-key trust, user and port are explicit. Agent, password, certificate, alternate config, proxy, multiplexing and forwarding fallback are disabled. A missing or changed key refuses before SSH or SCP starts. The temporary key copy and configuration belong to that invocation and are removed afterward.

The credential boundary does not claim isolation from hostile code running as the same operating-system user. It does not edit an operator's SSH configuration, known-hosts files, authorized keys or agent.

## Host implementation

The host half lives in `pairing.Host` and runs on the host machine as the operator: `pair offer`, `pair enroll`, `pair revoke` and `pair status` take `--state-root` instead of a client name. A paired key revokes itself through the stdin-JSON machine command `host pair-revoke`, which shares `Host.Revoke` and refuses unless the request carries that grant's own client-key fingerprint.

### Records and derived state

Three create-only records under `STATE_ROOT/pairings/` hold every durable fact: `offers/<offer_sha>.json` (the exact offer the client hashed), `grants/<pair_id>.json` (the request, resolved keys file, exact line and receipt) and `tombstones/<pair_id>.json` (the revocation request). Nothing is ever rewritten. The access state is derived from the two records plus the bytes sshd reads:

- No grant: `none`.
- Grant and no tombstone: `granting` while the line is absent, `granted` once present.
- Grant and tombstone: `revoking` while the line is present, `revoked` once absent.
- The exact line more than once: `conflict`. No command writes; the operator resolves it.

The marked line is the write-ahead record. Enroll publishes the grant, then appends the line. Revoke publishes the tombstone, then removes it. A crash between the two leaves a state from which the same command converges, and an enroll retry after a crashed revoke cannot re-add the key because the tombstone exists. This replaced the earlier proposal of one persisted pending before/after transaction: the line identity already says which transaction happened, and the before/after compare stays inside each keys-file edit.

Receipt bytes are `json.Marshal` of the receipt held in the grant, so a repeated `pair enroll --apply` returns identical bytes and the client's retained copy still matches. The grant records the receipt digest and any drift is a read error.

### Keys-file transaction

`Host` owns the line arithmetic (`internal/pairing/keys.go`): the line is `restrict <ssh-ed25519 key> blender-box-pair:<pair_id>`, appended with the file's own line ending and removed with exactly its own terminator, so every unrelated line keeps its bytes and order. The one accepted residue is a line ending added after a previously unterminated last line. A copy of the same key on another line, or this pair's marker with another key, refuses without writing.

The platform owns the edit. `ReadKeys` returns bytes, hash and security descriptor after refusing reparse points and descriptors sshd would reject. `ReplaceKeys` is one native transaction: verify hash and descriptor unchanged, create a temporary file in the same directory with the target descriptor before writing bytes, flush, `ReplaceFile` with a same-directory backup name for an existing file or a move for a new one, then re-read bytes and descriptor and require both. The backup matters: without one, a failed rename can leave no file at the path, and a retry would create an administrators file holding only the pairing line. With it, a failed swap moves the original back. A mismatch is an error, never a repair. A concurrent unrelated edit returns `ErrKeysChanged`; the retry re-reads and recomputes from the current bytes. Enroll re-reads the tombstone under the maintenance lock, so a revoke that finishes between the first read and the lock can never be undone. Revoke refuses to report `revoked` while the key or pair marker remains on any other line.

### Accepted tradeoffs

- The keys file is whichever `AuthorizedKeysFile` the host's own sshd resolves for the account through `sshd -T -C user=<account>,host=localhost,addr=127.0.0.1`. No sshd_config edit and no restart. For an Administrators account this is the shared `administrators_authorized_keys`, which admits the key for every Administrators account. The preview says so, the paired target pins the login user, and readiness proves the SSH SID equals the interactive SID. A `Match Address` or `Match Host` block that routes the real client elsewhere fails closed: the paired login is rejected and `doctor` reports it.
- `restrict` disables forwarding, pty and agent, so the Blender MCP port is never forwardable through the paired key. It still allows the exec and SFTP channels Runs and revocation use.
- Host-local approval is elevation: the operator runs the host verbs in an elevated PowerShell on the host or over an existing admin SSH channel. Commands refuse without elevation.
- Enroll and revoke mutate under `host.WithMaintenance`, so revoke refuses while a Run is active or unresolved. Offer and status change no access and take no lock.
- An abrupt exit can leave one `.blender-box-*.tmp` beside the keys file. It grants nothing and nothing deletes files by pattern.
- Existing authenticated SSH connections are a separate fact. Revocation removes the grant and proves new authentication is rejected; it does not terminate sessions.

### SSH preparation

`setup ssh` is its own typed request and receipt (`STATE_ROOT/ssh-preparation/<installation>.json`), outside the installation inventory and the installer's `Request`. Its plan is bounded: start sshd if stopped, set Automatic if not, and create one owned inbound rule `BlenderBox-SSH-<installation>` only when no enabled inbound rule already admits the port. It refuses when `pubkeyauthentication no`. Removal restores the prior start type only when the current type is still the one it set, deletes the rule only on exact match, and never stops sshd. A stock host produces an empty plan, no receipt and no change.

### Platform seam

A future platform implements `pairing.Platform` (identity facts plus the keys-file transaction) and an `SSHPreparer` for its own `setup ssh --platform`; readiness already lives in each platform's host adapter. The common flow, records and receipts do not change. The fake Linux platform test runs offer, client preparation, enroll, client completion and revoke end to end and yields a paired Linux target. Hosted pair-and-run against the real Windows host remains the acceptance gate for native behavior.

The hosted gate runs inside the retained `host-install` execution on the qualified proof controller. Its grant scope is `host-install-pair-run-remove`, because an installer grant does not authorize an `authorized_keys` change by implication. The controller keeps the client configuration, paired key, receipt, paired target and Run claim in its private store, and its installation chain records `pair-released` before the enrollment apply. Recovery from any pairing stage uses host-local `pair revoke --pair ID --apply` over the admin channel, or proves that no grant exists, and never replays enrollment. Removal refuses until the pairing is revoked and the declared keys-file pin matches again.

## Verification

Focused tests cover strict target parsing, alias schema compatibility, changed connection fields before Run recovery, local trust and retry behavior, secret-key checks, and both platform transport callers. Public CLI proof uses disposable keys and fake SSH/SCP processes. OpenSSH configuration parsing can be checked with `ssh -G` without contacting a host.

Host tests use a fake platform with an in-memory keys file: trust mismatch, canceled and interrupted enrollment at every checkpoint, duplicate apply with identical receipts, foreign key and marker refusal, a concurrent unrelated edit, revocation under Run authority, and an interrupted revocation. Windows CI runs the native keys-file transaction on a temporary file with the protected Administrators descriptor. `setup ssh` runs against a fake service and firewall.

The full repository gate remains `./scripts/ci all`. Windows cross-compilation establishes compilation only. Native `sshd -T` resolution, Windows client credentials, Blender, and hosted pairing remain separate proof requirements.
