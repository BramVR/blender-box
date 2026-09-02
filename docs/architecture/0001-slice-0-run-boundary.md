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
blender-box windows setup --target target.json --host-binary blender-box.exe --json
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
    Status(context.Context, Target, RunID) (StatusResult, error)
    Stop(context.Context, Target, RunID) (StopResult, error)
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

The Host Lock is the authority record. The Windows host creates it atomically before staging. Every later host mutation compares the complete claim. An acquisition error is ambiguous because the remote create may have committed before its response was lost, so the client makes one bounded claim-only settlement attempt. Once `blendersessiond start` returns, the host adds the opaque Session identity with a compare-and-replace write. Session Name remains a routing label, but the typed request must use the exact name derived from its Run ID so launch and settlement cannot route differently. Daemon `call` and `stop` also require the Session identity, so a replaced record fails closed at both layers.

Payload transfer canonicalizes the declared document root, accepts regular files beneath it, rejects symlinks and traversal below that pinned root, caps file count and total bytes, and verifies SHA-256 before publishing the request. Evidence uses the reverse rule: only manifest-declared regular files under the Run root return, with a per-file and total byte cap. Before host inspection, the local client reserves a fresh, exclusive Evidence Bundle directory so a destination collision cannot discard completed remote evidence. It verifies remote hashes after transfer and never replaces an existing evidence file.

The controller filesystem belongs to the invoking user. Blender Box rejects static symlinks, snapshots validated payload bytes, creates evidence atomically, and detects ordinary source changes; it does not claim isolation from an actively hostile process running concurrently as that same OS user. Such a process can already read and replace controller-owned files. Consuming automation must use a private payload and evidence tree when other local users are in scope.

The Windows task runs as the logged-in controller identity with `LogonType=Interactive`, limited rights, no trigger, `IgnoreNew`, and no execution time limit. Slice 0 requires the SSH controller and interactive task to resolve to the same SID; separate identities are deferred by ADR 0002. Explicit setup is plan-only unless `--apply` is present. Apply validates identity equality, existing path components, fixed-volume authority, and every work-root ancestor owner and replacement right before writes. Its prepare and publish phases take the same byte-range `.operation.lock` as the Go host, then recheck the Host Lock, physical paths, and any existing host destination while holding it; that destination must be a regular non-reparse file. A Run cannot acquire authority during setup mutation. Random SCP staging remains outside the critical section because no Run or task references those files. While locked, setup seals every component between the declared root and each managed executable directory. It creates and seals the required `runs` and `receipts` directories, then validates and seals each existing entry parent-first without following reparse points. Later inspection requires both state directories and accepts runtime entries only under those sealed parents, with the shared identity's authority and no untrusted writer. Managed executables must live below a dedicated directory and cannot descend from the reserved state trees. The shared identity owns the root, state entries, executable directories, managed files, and task management authority, keeping repeat apply non-elevated. Setup uses SCP for one non-empty bounded host binary and one bounded setup program because large PowerShell stdin and near-limit command lines are not reliable on Windows OpenSSH; only the small bounded guard uses the proven stdin bootstrap. A short bootstrap verifies the setup-program hash before executing it in memory; the program rehashes and atomically publishes the host binary, applies matching path and task ACLs, and removes its exact staging files. Target validation rejects case-insensitive collisions among the host, daemon, and Blender executable paths before setup can write. The task starts the host entry point, which validates the request and lease again before invoking `blendersessiond`. Blender's MCP port remains Windows-loopback-only.

Host mutations use an OS-released file lock rather than a crash-sticky sentinel. The task holds it only while publishing or comparing authority and durable state. Daemon startup holds a separate OS-released launch lock while the global operation lock is free. Settlement can recover and stop a published Run-isolated daemon identity during startup; if no identity exists while the launch lock is held, it retains authority and fails bounded rather than claiming cleanup. After `blendersessiond start`, the task reacquires authority and publishes the exact Session identity before waiting for readiness. If Host Lock publication fails, exact rollback uses the independent reconciliation deadline rather than the expired Run deadline. If rollback also fails, the receipt retains the Session identity and settlement adopts it only after Run-isolated daemon recovery returns the same opaque identity. If the task crashes between identity writes, settlement likewise queries only the Run-isolated daemon state, adopts its valid identity into the exact Host Lock, and stops through that identity. `blendersessiond` records the identity before opening its Windows Blender-launch gate, so `not-found` is safe claim-only recovery when no launch remains active. The client replays only the identical fenced start request while the receipt remains identity-free, preventing `IgnoreNew` from losing the only trigger. The task releases the operation lock and polls `status` for up to two minutes, requiring both the same Session identity and healthy process/socket state. Readiness, long Scenario, and capture calls run outside the lock, then reacquire it and revalidate the complete claim and exact Session identity before committing evidence. This lets `stop` interrupt startup or a running call without allowing the interrupted task to recreate settled state.

Recovery reads the receipt through the same SSH adapter. A dropped connection does not release the Host Lock. `status` can report accepted, staged, starting, running, calling, collecting, settling, complete, failed, timed-out, or cleanup-failed. A receipt without its Host Lock and every terminal receipt permanently reserve their Run ID; acquisition cannot reset them to accepted. `stop` requires the Run ID, request identity, request hash, deadline, and Session identity from the receipt. The controller-selected target supplies the daemon executable on the settlement request, and the Session name is derived from the Run ID; task-writable Run state never selects a process invoked by the SSH controller. Receipt cleanup flags are hints only while a Host Lock or Run root remains, so settlement repeats the exact idempotent stop and reconciles physical cleanup instead of returning early. Settlement changes an interrupted nonterminal receipt to `failed` before publishing final cleanup and preserves `complete`, `failed`, `timed-out`, or `cleanup-failed`. After settlement the client re-observes the durable receipt, revalidates the full claim and any previously known Session identity, and returns a Session identity recovered during startup cleanup. Cleanup records Session stop, Run-root cleanup, and lock release separately. If the daemon already removed that exact Run-isolated Session but the host crashed before recording the stop, structured `not-found` is an idempotent stop result; any replacement identity still fails closed. Run-root deletion preserves `ownership.json` until every other entry is gone, retries only Windows sharing violations within the existing 30-second settlement bound, and removes only an otherwise empty non-reparse Run directory if ownership is missing. Any remaining entry fails closed.

This interface is deep because four user operations hide transport quoting, atomic host state, identity comparison, transfer bounds, task polling, daemon JSON, evidence verification, reconnect, and settlement. The public CLI does not expose those phases as switches.

Before either setup connection writes, the authenticated Windows SID must equal the target's declared SSH user SID. Setup never turns an alias-selected account into controller authority by observation. Lock acquisition checks cancellation before touching a free lock. After each daemon boundary, state reconciliation uses its own bounded context, revalidates exact Run and Session authority, and persists an expired Run as `timed-out`; deadline races cannot leave a cleaned Run in a nonterminal state.

Read-only inspection proves that the SSH controller, console user, and interactive task share one SID. It also proves explicit controller FullControl on the sealed state roots, executable directories, and executable files; runtime state descendants may inherit that authority only from the sealed roots. Only the shared identity and privileged Windows principals may own or hold replacement authority on ancestors of the work root. The work root uses a narrow legacy-SCP-safe ASCII path grammar, enforced by target validation and again by the upload transport. A complete Run accepts exactly one Scenario Result and exactly one requested viewport capture, with no unsolicited evidence types. The decoded Scenario Result remains capped at 1 MiB; daemon process output allows twice that size plus fixed envelope headroom for nested JSON escaping. The public `stop` command performs its final durable receipt observation under a fresh bounded reconciliation context, so caller cancellation during settlement cannot suppress the returned exact Session identity and known cleanup state. Repeating exact stop for a settled Run returns its known cleanup even while a different valid Run owns the Host Lock, without changing the newer Run's lock or pending request.

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

- Failure runs currently return their durable receipt and cleanup state, but full failure Evidence Bundles remain later work.
- A Scenario read timeout is capped at 3,600 seconds; later render workloads may justify a different bounded contract.
- Slice 0 proves viewport evidence only. It does not claim Blender-window chrome or Windows-desktop proof.

## Implementation status

The first landed seam is `windows check --target <file> --json`. One Go binary serves both the client and the static task entry point; Python remains inside Blender-owned Scenario scripts. The check streams a bounded read-only PowerShell program over SSH, resolves the configured console user to an SID, and validates declared paths and the root Scheduled Task without relying on the SSH user's `PATH`.

The Run contract and deterministic orchestration core are implemented behind `Runner`. A strict Payload loader snapshots the validated bytes, computes transfer size and SHA-256 locally, rejects unsafe Windows paths and symlinks, and enforces file and aggregate bounds. The integrated fake-host test proves the full ordering from inspection and Host Lock acquisition through an exact versioned Session receipt, hash-verified evidence, and known settlement without exposing adapter phases in the CLI. The Run deadline bounds every normal adapter operation; settlement has a separate 30-second attempt bound and retains the last trusted authority after cancellation or transport failure.

The public `windows setup`, `run`, `status`, and `stop` commands now enter through the boundaries above. Setup is plan-only by default and uses bounded SCP staging plus independent script and binary hashes. The Windows adapter carries versioned JSON over SSH; the static task invokes the same binary's private `host run-request` entry point. The host rehashes published payload bytes before launch, stores the exact daemon Session identity in the Host Lock, waits for exact-session health, and fences every daemon call and stop with it. Evidence files must be non-empty; viewport PNG dimensions are decoded and compared with declared provenance before the host publishes its receipt and again after the client fetches the bytes. Cleanup keeps ownership proof until the last deletion and absorbs transient Windows log-handle release within its bounded settlement attempt.

`run` publishes its Run ID on stderr before validation or remote work while reserving stdout for one versioned success or failure JSON document. Local preflight failures do not contact the host. After a later orchestration failure and bounded settlement, JSON mode attempts one bounded `status` recovery so the result includes the durable receipt and cleanup facts; it preserves failure state when host completion preceded a local evidence failure. If the host is unreachable it reports only facts known locally. The returned Evidence Bundle contains a no-replace `manifest.json`, terminal `evidence.json`, the Scenario Result, and optional viewport capture with dimensions and capture method. `status` provides a reconnect view; `stop` recovers the exact claim and Session authority from host state, including interrupted receipt publication, partial acquisition, and final-receipt crash windows.
