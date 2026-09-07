---
summary: Local pairing pins SSH identity and preserves approval and publication recovery separately from host readiness.
read_when:
  - Changing paired target schema, client credentials, pairing trust, or local reconciliation.
  - Implementing native pairing or extending its hosted proof.
---

# Client pairing

## Decision

A paired target binds the direct endpoint, login, Ed25519 host public key and dedicated client-key fingerprint. Schema version 3 carries that connection alongside one existing Windows or Linux body. It uses the existing target store and original Run fingerprint. Alias schemas 1 and 2 retain their exact canonical bytes and fingerprints.

The local client requires a separately trusted host offer and enrollment receipt. Windows `setup ssh` also provides a read-only preparation preview through the existing installation owner. SSH apply, native offer creation, enrollment and revocation remain unsupported. No command turns local preparation into a successful host enrollment or readiness check.

## Local workflow

`pair prepare NAME --offer PATH --trust-offer SHA256` verifies an offer against a digest obtained through an independent trusted channel. A JSON file alone supplies no trust. The offer binds its expiry, bootstrap and installation identities, account and root identities, installed target, and exact server endpoint.

Preparation checks the complete retained record's size before creating credentials. It durably reserves the name, offer and request IDs, then retains one winning Ed25519 seed under that preparation. Concurrent callers use the same reservation and seed. The client derives the key in memory, retains the immutable enrollment intent, publishes the fingerprint-addressed credential, and exports only the public request. A repeated preparation returns the original intent after checking its key. A different offer or preexisting target name refuses.

The seed reproduces the original OpenSSH private key after an interrupted publication. New preparation paths validate durable credential bytes without temporary private-key copies outside pairing storage. Legacy intents without a reservation retain their existing credential checks. The unencrypted single-Ed25519 encoding follows [OpenSSH's key format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key); tests verify it with the real `ssh-keygen` reader.

`pair complete NAME --receipt PATH --trust-receipt SHA256` verifies the independent receipt digest, then matches the receipt against the retained Pair ID, operation, intent, public key and complete expected target. It retains the accepted receipt before saving the target. Saving uses `target.Store.Save`, the same publication path as import, without replacing an existing profile.

A lost response or interrupted publication leaves the original intent, key and accepted receipt available for retry. An unrelated replacement target remains untouched. Completion can reconcile a receipt after the original offer expires because the host may already have applied the request. Fresh preparation requires an unexpired offer. Interrupting the client does not revoke remote access or erase pending recovery material.

`pair status NAME` reports access and readiness separately. An interrupted preparation reports its retained Pair ID and directs you to repeat preparation with the original offer. `prepared-unconfirmed` means that the client has no accepted enrollment receipt. Accepted receipt state can still need target publication. A saved matching target reports enrolled access with unchecked readiness. The next operational step is `doctor` with the intended Scenario payload.

## Credential and transport boundary

Keys live under `credentials/<fingerprint>/id_ed25519` in the private user configuration root. The fingerprint is lowercase hexadecimal SHA-256 of the canonical SSH public-key wire bytes, not OpenSSH's display string. POSIX reads enforce current-user ownership, private permissions, bounded regular files, and a matching derived public key. Windows key operations refuse until native owner and ACL enforcement exists.

Retain the preparation and seed as private recovery material. Each globally published key has a durable intent naming it. An abrupt process exit can leave atomic-publication temporary copies beneath the original preparation or that intent's fingerprint directory. Those copies remain attributable to the pairing; their count is not bounded, and preparation does not sweep or delete credentials.

The shared transport accepts one `target.Connection`. Alias connections retain operator configuration. Paired SSH and SCP use the same generated private configuration and verified key copy. Host-key trust, user and port are explicit. Agent, password, certificate, alternate config, proxy, multiplexing and forwarding fallback are disabled. A missing or changed key refuses before SSH or SCP starts. The temporary key copy and configuration belong to that invocation and are removed afterward.

The credential boundary does not claim isolation from hostile code running as the same operating-system user. It does not edit an operator's SSH configuration, known-hosts files, authorized keys or agent.

## Remaining host implementation

Native enrollment will use the approved single current owned store snapshot and one exact pending before/after transaction. Immutable grant receipts and terminal tombstones preserve retry and revocation facts. No generation history or second target registry is planned.

The Windows owner must prove its account-scoped authorization source, physical identities, ACLs, serialized publication, interruption recovery and preservation of unrelated access. Revocation must refuse active or unresolved Runs and distinguish exact grant removal from fresh authentication rejection. Existing authenticated SSH connections are a separate fact.

SSH preparation requires an explicit owned setup operation with its own preview and authority. The current installer and proof controller do not authorize it by implication. Hosted pair-and-run must use the actual qualified controller and retain private original Run authority. Local tests, accepted receipt fixtures and this CLI slice do not satisfy native or hosted acceptance.

The [Windows SSH preview](../windows-ssh-preparation.md) binds the request, installed receipt and runtime, file identities and ACL digests, account membership, configured host-key provenance, current configuration, proposed bytes and permissions, effective policies, service and firewall facts. Repeated observations reject changed dependencies. The existing owner supplies this read-only operation without extending installation execution authority. Current policy comes from the installed `sshd`; the proposed policy is predicted until apply validates the staged file natively. Preview creates no state or fence. Existing `Include` and `Match` configurations remain outside this initial subset, including the default Windows administrator block.

Preview retains one Windows read scope across both observations and the final maintenance check. Canonical external paths resolve through captured fixed-volume anchors and retained parent handles; each newly discovered child requires a no-follow open. The host package supplies one maintenance policy through bounded `Stat`, `ReadDir` and `ReadFile` observations. Windows path mechanics stay in the installer. Directory handles do not freeze membership or ACLs, and repeated enumeration detects changes without proving atomic absence. Native execution must verify sharing behavior and installed-tool compatibility with the physical paths.

The installed OpenSSH 9.5 parser runs with `-G -T -C` so it dumps the selected account's current configuration before loading private host keys. Native command paths use the captured physical volume; tool failure refuses preview. PowerShell module caching is disabled for those child processes. The volume query is allowed before descendant opens; this contract does not claim zero operating-system network traffic.

## Verification

Focused tests cover strict target parsing, legacy compatibility, changed connection fields before Run recovery, local trust and retry behavior, secret-key checks, and both platform transport callers. Public CLI proof uses disposable keys and fake SSH/SCP processes. OpenSSH configuration parsing can be checked with `ssh -G` without contacting a host.

The full repository gate remains `./scripts/ci all`. Windows cross-compilation establishes compilation only. Native Windows/Linux credential behavior, host enrollment, Blender, revocation and hosted pairing remain separate proof requirements.
