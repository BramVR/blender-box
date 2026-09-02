# Blender Box

Blender Box is a remote Blender GUI Scenario runner for owned Windows hosts. A client runs from a developer checkout, reaches Windows over SSH, stages a declared Run Payload, starts Blender in the logged-in desktop through an interactive Scheduled Task, drives the host-local `blendersessiond`, and returns structured and visual evidence.

The direct SSH adapter is the default. Tailscale supplies private host reachability without becoming part of the application protocol.

## What makes Blender Box special?

Blender Box is new. The research has already identified the things we can never compromise on as we build the product.

### 1. Open at the core

Blender Box is truly open. We share our roadmap, we share how we think about things, and of course we share all our code. We work in the open, and should strive to stay that way.

### 2. Remote ready

The default run starts on the developer machine and crosses the Tailnet over SSH. Tailscale supplies reachability today, but Blender Box accepts a safe SSH config alias so LAN, another VPN, or a bastion can replace it without changing Scenario config. Make sure new features work through the remote Windows adapter and do not assume local Blender access.

### 3. Safe process ownership

Remote GUI automation can damage unrelated work when identity is vague. Every destructive action must prove the Run ID, request identity, deadline, and exact daemon Session identity. Blender Box stops only the process tree its Session owns. A stale Run must never stop or clean a newer Session.

### 4. Evidence without compromise

A run is not complete until evidence returns to the client and remote cleanup is known. Logs, Scenario Result JSON, declared outputs, hashes, screenshots, validation, and cleanup state are part of the product contract. Viewport, Blender window, and Windows desktop captures are different evidence types and must remain named as such.

## A note for agents

I like ambitious ideas, simple systems, and software that feels obvious. Do not preserve complexity just because it already exists. Do not introduce machinery because it looks architecturally impressive. Understand the real constraint, then fight for the smallest model that makes the correct behavior unsurprising.

Channel both "measure twice, cut once" and "yagni". Fight scope creep. Try to honor the dev's intent in both a minimal and realistic fashion.

The rest of this document is meant to help you navigate the codebase and make changes effectively. Think of these instructions less as "hard rules", more as "good defaults". The developer's preferences should be able to override anything here.

Of note: Most Blender Box development happens from a developer machine that may also control a real Windows desktop. This means you should be careful about accessing operator state, stopping processes, changing Scheduled Tasks, and other things that may damage the Blender host that the developer is using.

## A small glossary

We need to be on the same page with terminology. When communicating, use this language:

- **you** means the agent reading this file and changing Blender Box.
- **we, us, and maintainers** mean Bram and the people building Blender Box. These are who you are talking to now.
- **user** means the person using Blender Box to run a Scenario.
- **Scenario** means the consuming repo's declared Blender workflow, payload, expected outputs, evidence policy, and validators.
- **Run** means one accepted execution of a Scenario, identified by an immutable Run ID.
- **Run Payload** means the typed, declared files and execution intent staged for a Run.
- **target profile** means the operator-selected host configuration used by a Scenario.
- **host** means the owned Windows machine that runs Blender in a logged-in interactive desktop.
- **Host Lock** means the host-owned authority record that fences one Run across repos and controllers.
- **Session** means one `blendersessiond`-owned Blender lifecycle.
- **Session identity** means the opaque daemon identity required for later call, capture, stop, attach, and cleanup operations. A Session name is only a routing label.
- **evidence** means the structured results, logs, captures, outputs, hashes, validation, and cleanup facts returned for a Run.

## The three ways to hurt yourself

1. **Killing by pattern.** Never `pkill -f`, `pgrep | kill`, `taskkill /IM`, or kill a PID you found by matching a name, path, Session name, or worktree string. This machine may run unrelated Blender processes and other development work at once. Stop only through an exact `blendersessiond` Session identity, or a PID and process start time captured from a task-owned spawn.
2. **Writing to the live host.** Setup commands are read-only unless an explicit apply flag is present. Never move, delete, rewrite, or reset another application's caches, databases, configuration, profiles, sessions, keychains, credentials, Blender roots, or operator files. A Run may write only inside its validated run root and declared outputs. Cleanup requires exact Run and Session ownership.
3. **Exposing the Blender port.** The Blender MCP add-on remains bound to Windows loopback. Never expose it, forward it over SSH, bind it to the Tailnet, or turn it into Blender Box's application protocol. SSH owns control and file transfer. `blendersessiond` invokes the add-on on the same machine.

## Hit every boundary

The most common defect in a remote runner is a change that works on the path you tested and is missing everywhere else. Before calling orchestration work done, walk this list and say which entries applied:

- **Commands.** A Run behavior may affect `plan`, `doctor`, `run`, `status`, `attach`, `stop`, history, expiry, and setup checks. Fixing one is not fixing the feature.
- **Boundaries.** The client, SSH transport, Windows adapter, interactive Scheduled Task, `blendersessiond`, and Blender GUI have separate responsibilities. Keep the seam explicit.
- **Contracts.** Anything crossing SSH or a process boundary needs a typed or versioned contract. Change the schema and every producer, consumer, status path, and recovery path must follow.
- **Reverse states.** If you added a way in, add the way out and the way to see it. Keep needs stop. Lock needs release. Setup apply needs a read-only check. A one-way door is a bug.
- **Connection states.** Clean completion, Scenario failure, timeout, dropped SSH, client restart, stale request, kept Session, and expired Session behave differently. Recovery cases are real.
- **Evidence.** Success and failure need bounded manifests. Record provenance, exact Session identity, remote and local SHA-256, capture type, validation, and cleanup facts.
- **Docs.** Behavior changes that a user would notice belong in user documentation. Architecture and contributor changes belong in durable project docs. Runbooks should state their audience and safety boundary. Update the research brief when implementation decisions replace its proposals.

## Remote Windows runs

- Tailscale currently provides private host reachability through the configured SSH alias. Do not put private hostnames, Tailnet addresses, Windows users, SSH keys, credentials, or operator paths in repo config, docs, tests, or fixtures.
- Windows OpenSSH is not an interactive GUI launcher. SSH writes an atomic, fenced request and triggers the declared passwordless Scheduled Task for the logged-in interactive user. Blender never starts as an OpenSSH child.
- The static task calls `blender-box host run-request` against a fixed operator-managed state root. It must use limited rights, an interactive logon, no trigger, `IgnoreNew`, and no execution time limit.
- `blendersessiond` remains same-machine and owns Blender discovery, launch, health, raw calls, loopback port allocation, logs, unsaved state, and exact process-tree stop.
- Acquire the shared Windows Host Lock before staging or starting. Bind it to the Run ID, controller, deadline, request hash, task name, and returned Session identity.
- Stage only declared files into a clean per-run root. Validate paths, reject unsafe symlinks, use bounded transfer, and isolate Blender user config, scripts, extensions, and data roots.
- Stop what you started, by the exact Run and Session identity you tracked. See rule 1.

## Test boundaries

An all-fake happy path is a bad test, but real Windows Blender proof does not belong in the default suite.

- Default tests use fake SSH, Scheduled Task, daemon, filesystem, and Blender boundaries. They cover failures, reconnects, stale identities, cleanup, and bounded transfer without touching a real host.
- Scenario scripts and consuming repos own Blender-domain correctness. Core validators stay generic.
- Live behavior needs opt-in proof against the declared Windows host with the interactive user logged in. Never infer permission to launch Blender, apply setup, change a task, or stop an existing Session.
- Use task-local directories and fake operator values. Never copy private hostnames, Tailnet addresses, Windows users, credentials, or operator paths into fixtures or snapshots.
- Data flows one way: declared payload into the Run, declared evidence back out. Never let a test write back into a consuming repo or shared host state.

## Verifying

- Smallest proof that the change works. Run focused tests for the behavior you touched, targeted lint and typecheck for the scope you changed, then the full repository gate before handoff.
- Test meaningful logic or observable behavior. Do not add tests that merely assert callback wiring or mirror the implementation.
- Bugs ship with focused regression tests when the boundary can be reproduced safely.
- Async flows wait on explicit state, events, or receipts, never on sleeps. A test that needs a timing guess to pass is wrong.
- User-facing live changes should get one integrated pass through a real Scenario when the user authorizes Windows Blender proof. Record the Run ID, exact Session identity, evidence, and cleanup result.
- Run `./scripts/ci all` for the full local gate. Add exact Go, Python, release, and live-proof commands there as those choices land.

## Pull requests

- Never make a PR unless the developer explicitly asks you to do so.
- Conventional commit titles, plain language: `fix(host): stale runs no longer stop replacement sessions`.
- Use `committer`; stage only named paths.
- Body: the problem in a sentence or two, then how you fixed it. End with the model and harness that did the work.
- User-visible changes need evidence. UI, viewport, window, or render changes need before/after images when those images prove the behavior. Motion or timing needs a short video.
- Upload PR evidence to GitHub. Never commit PR-only screenshots or assets.
- One concern per PR. If the description says "also", split it.
- When babysitting: poll checks and comments newer than the last push, verify each bot finding against the source, fix real ones, dismiss false positives with a written reason. Stay quiet when nothing is new. Stop when the bots are green on the latest commit.

## Plans and work artifacts

- Do not commit implementation plans, agent scratch files, or temporary host data. Keep temporary working material outside the worktree.
- The research brief is the current durable product record. Update it when implementation decisions replace proposals, and move stable architectural decisions into ADRs before their assumptions spread through the code.
- Track active maintainer work in the GitHub issue or project item that owns it when one exists.
- A merged PR is the implementation record. Close or update its tracking item when the work lands; do not preserve a second checklist in the repository.
- Evidence Bundles are product artifacts, not agent scratch. Store them under the declared `artifacts/blender-box/<run-id>/` layout and keep secrets and private network details out.

## How it works

The client accepts a Scenario and creates a Run ID before validation. It resolves the target profile, plans declared transfer, checks the Windows host over SSH, acquires the shared Host Lock, and stages a clean run root. SSH atomically writes a fenced request and triggers a static Scheduled Task in the logged-in desktop. The task starts same-machine `blendersessiond`, which owns the Blender process tree and loopback MCP connection. The client invokes Scenario work through the daemon, returns and verifies evidence, runs local validators, then stops or keeps the exact Session according to policy and records cleanup before finalizing the Run.

Tailscale supplies reachability, not application protocol. Scenario scripts and consuming repos own Blender-domain truth. Blender Box owns orchestration, evidence, and recovery. `blendersessiond` owns process authority.

Full research and proposed contracts: `docs/research/blender-box-research.html`

## Where code lives

- `README.md` - product summary and current status.
- `docs/research/blender-box-research.html` - research basis, architecture, proposed contracts, evidence layout, risks, and build order.
- `docs/architecture/ci.md` - local and hosted CI boundary, tradeoffs, and live-proof separation.
- `scripts/ci` - the local and GitHub Actions check/test entrypoint.
- `AGENTS.md` - repo-local operating notes.
- `cmd/blender-box` and `internal/cli` - public command parsing and JSON output.
- `internal/target`, `internal/ssh`, and `internal/windows` - typed target config, bounded SSH process boundary, and Windows inspection adapter.
- Do not invent a generic DCC core before the product proves a stable need for one.

## Taste

- Complexity belongs at the adapter boundary. Orchestration stays deterministic, host authority stays explicit, and Scenario scripts own domain behavior.
- Names are routing labels, not authority. Require opaque identity for destructive or stale-sensitive operations.
- Setup is read-only by default. Remote writes require an explicit apply flag and a bounded target.
- Comments describe how a thing is used, and move when the code moves. Use them mostly to describe functions and dangerous invariants, not to annotate every line of behavior.
- Evidence says what it proves. An offscreen viewport image does not prove UI chrome, and a Blender window image does not prove an OS dialog.
- Fresh runs get isolated Blender roots. `--factory-startup` alone is not isolation.
- If a rule here fights the task in front of you, say so loudly and get a human sign-off before breaking it.

## Additional tips

- Don't verify against a real Windows host, launch Blender, apply setup, or use computer control unless the user explicitly agrees or requests it.
- Do not add a Control Plane, durable queue, host pool, provider fleet, or WebVNC portal before a direct SSH run proves the need.
- Security and process ownership are part of correctness. Do not weaken exact fencing for dev mode or maintainer-only features.
