---
summary: Slice 0 client, Windows host, and blendersessiond ownership contract.
read_when:
  - Changing Run orchestration, Windows requests, Host Locks, daemon calls, evidence, or cleanup.
---

# Slice 0 run boundary

## Problem

Slice 0 must cross a developer checkout, SSH, an interactive Windows task, `blendersessiond`, and Blender without spreading ownership rules through every command. A dropped client must be able to recover, while a stale client must be unable to replace a Host Lock, call a replacement Session, stop it, or clean its files. The public CLI also needs stable JSON before the full Scenario format exists.

## Usage

The user supplies one non-secret target file and one explicit Run Payload. Slice 0 keeps the public commands to inspection, execution, recovery, and exact stop:

```console
blender-box windows check --target target.json --json
blender-box run --target target.json --payload payload.json --json
blender-box status --target target.json --run bbx_... --json
blender-box stop --target target.json --run bbx_... --json
```

`run` returns a Run ID before remote work starts. Its terminal JSON names the request identity, exact daemon Session identity, Evidence Bundle, and cleanup state. If the connection drops, `status` reads the host-owned receipt and `stop` settles only the exact identities recorded there.

The host task has one fixed entry point. Operators register it with a fixed state root during explicit setup:

```console
blender-box host run-request --state-root <operator-managed-root>
```

The task reads the single atomically published request selected by the host adapter. It does not accept arbitrary commands, paths, or environment values from the Scheduled Task action.

## Shape

The client uses one deep orchestration interface:

```go
type Runner interface {
    Run(context.Context, RunIntent) (RunResult, error)
    Recover(context.Context, RunRef) (RunStatus, error)
    Stop(context.Context, StopIntent) (StopResult, error)
}

type RunIntent struct {
    RunID       RunID
    RequestID   RequestID
    Deadline    time.Time
    Target      Target
    Payload     Payload
    EvidenceDir string
}

type HostAdapter interface {
    Inspect(context.Context, Target) error
    Acquire(context.Context, Target, LockClaim) error
    Stage(context.Context, Target, LockClaim, Payload) error
    Start(context.Context, Target, RunRequest) (RunReceipt, error)
    Observe(context.Context, Target, RunID) (RunReceipt, error)
    Fetch(context.Context, Target, RunReceipt, EvidenceFile) ([]byte, error)
    Settle(context.Context, Target, RunReceipt) (CleanupState, error)
}
```

The exported methods reflect user operations. `Runner.Run` owns the complete state machine and always attempts settlement after a lease exists. Callers never coordinate adapter phases themselves. `HostAdapter` is a system boundary for the remote Windows implementation and fakes, not a public user API.

Contracts crossing SSH or a process boundary use versioned JSON. Required authority fields are non-optional and repeat on every stale-sensitive request:

```go
type LockClaim struct {
    SchemaVersion int
    RunID         RunID
    RequestID     RequestID
    ControllerID  string
    Deadline      time.Time
    RequestHash   SHA256
    TaskName      string
}

type RunReceipt struct {
    SchemaVersion int
    Claim         LockClaim
    State         RunState
    SessionID     SessionID
    Evidence      EvidenceManifest
    Cleanup       CleanupState
}
```

The Host Lock is the authority record. The Windows host creates it atomically before staging. Every later host mutation compares the complete claim. An acquisition error is ambiguous because the remote create may have committed before its response was lost, so the client makes one bounded claim-only settlement attempt. Once `blendersessiond start` returns, the host adds the opaque Session identity with a compare-and-replace write. Session Name remains a routing label. Daemon `call` and `stop` also require the Session identity, so a replaced record fails closed at both layers.

Payload transfer canonicalizes the declared document root, accepts regular files beneath it, rejects symlinks and traversal below that pinned root, caps file count and total bytes, and verifies SHA-256 before publishing the request. Evidence uses the reverse rule: only manifest-declared regular files under the Run root return, with a per-file and total byte cap. The local client verifies remote hashes after transfer into a fresh, exclusive Evidence Bundle directory and never replaces an existing evidence file.

The controller filesystem belongs to the invoking user. Blender Box rejects static symlinks, snapshots validated payload bytes, creates evidence atomically, and detects ordinary source changes; it does not claim isolation from an actively hostile process running concurrently as that same OS user. Such a process can already read and replace controller-owned files. Consuming automation must use a private payload and evidence tree when other local users are in scope.

The Windows task runs as the logged-in user with `LogonType=Interactive`, limited rights, no trigger, `IgnoreNew`, and no execution time limit. It starts the host entry point, which validates the request and lease again before invoking `blendersessiond`. Blender's MCP port remains Windows-loopback-only.

Recovery reads the receipt through the same SSH adapter. A dropped connection does not release the Host Lock. `status` can report accepted, staged, starting, running, calling, collecting, settling, complete, failed, timed-out, or cleanup-failed. `stop` requires the Run ID, request identity, request hash, deadline, and Session identity from the receipt. Cleanup records Session stop, Run-root cleanup, and lock release separately.

This interface is deep because four user operations hide transport quoting, atomic host state, identity comparison, transfer bounds, task polling, daemon JSON, evidence verification, reconnect, and settlement. The public CLI does not expose those phases as switches.

## Synthesis decision

Candidate A, one Run state machine behind `Runner`, is the base. Candidate B split planning, lock management, transfer, task launch, daemon calls, evidence, and cleanup into command-layer services that the CLI coordinated. That made each component locally simple, but it leaked execution order and fencing rules into every caller. Candidate A keeps Candidate B's explicit typed boundary adapters for tests while refusing its public phase orchestration.

Two details from Candidate B remain: host operations are individually observable in the receipt, and each external boundary has a narrow fake. These make recovery and tests precise without turning internal steps into a user API.

## Tradeoffs accepted

- We accept a single state-machine module with substantial policy in exchange for one place that guarantees settlement and identity checks.
- We accept duplicated fence fields in host and daemon requests in exchange for independent stale-client rejection at both ownership boundaries.
- We accept a slice-specific JSON Payload instead of the final Scenario YAML in exchange for proving the remote contract before fixing the broader Scenario format.
- We accept explicit `status` and `stop` commands in slice 0 because reconnect without a visible and safe way out would be incomplete.

## Alternatives considered

Candidate B exposed each execution phase as a service used directly by CLI commands. It hid little. Every caller had to know when to acquire, stage, start, fetch, stop, clean, and release, and one missed phase could leak a lock or stop the wrong Session.

A host-side all-in-one service with an HTTP or forwarded MCP endpoint would shorten client code, but it would add a network protocol, listener, authentication problem, and daemon scope that slice 0 does not need. SSH already provides the authenticated control and transfer channel.

A Python-only client and host helper would make the first code quick to write, but cross-compiling one Go binary gives the client and static Windows task the same versioned contracts. Python remains inside Blender Scenario scripts, where Blender owns the runtime.

## Open questions and risks

- Does `blendersessiond` need one dependency PR or separate identity and timeout PRs to keep each change reviewable?
- Which hard maximum for a Scenario call is high enough for a real render while still bounding a stuck add-on?
- Does Windows OpenSSH on the proof host support the chosen bounded archive stream without an extra tool, or should slice 0 transfer files one at a time through standard input?
- Which evidence capture types can the first real proof support without claiming Blender-window or desktop proof from viewport pixels?

## Implementation status

The first landed seam is `windows check --target <file> --json`. One Go binary serves both the client and the future static task entry point; Python remains inside Blender-owned Scenario scripts. The check streams a bounded read-only PowerShell program over SSH, resolves the configured console user to an SID, and validates declared paths and the root Scheduled Task without relying on the SSH user's `PATH`.

The Run contract and deterministic orchestration core are implemented behind `Runner`. A strict Payload loader snapshots the validated bytes, computes transfer size and SHA-256 locally, rejects unsafe Windows paths and symlinks, and enforces file and aggregate bounds. The integrated fake-host test proves the full ordering from inspection and Host Lock acquisition through an exact versioned Session receipt, hash-verified evidence, and known settlement without exposing adapter phases in the CLI. The Run deadline bounds every normal adapter operation; settlement has a separate 30-second attempt bound and retains the last trusted authority after cancellation or transport failure.

The remaining `run`, `status`, and `stop` commands and Windows adapter must enter through the `Runner` boundary above. They must not expose host adapter phases as public CLI switches.
