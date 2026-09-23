# Blender Box verification map

This map covers public CLI workflows against explicitly authorized owned Windows and Linux Blender hosts. Read the index first, then the feature recipe being proved.

## Windows baseline preconditions

- Build the client and Windows host binary from one exact checkout in a disposable `VERIFY_ROOT`.
- Set `BLENDER_BOX_TARGET` to an operator-supplied target outside the repository.
- Set `BLENDER_BOX_EXPECTED_HOSTNAME` and prove it before any setup write.
- Require an interactive Windows user, installed Blender, exact compatible `blendersessiond`, private SSH reachability, and no unknown Blender Session or Host Lock.
- Never expose or forward Blender's loopback MCP port.

## Driving conventions

- Run commands from the repository root.
- Treat stderr `RUN_ID=` as the pre-work recovery handle and stdout as one versioned result document.
- Use public Windows installation `setup`, `windows check`, legacy `windows setup` preview, or `linux check/setup`, then shared `plan`, `doctor`, `run`, `status`, and `stop` entry points.
- A Session name routes; only the opaque `session_id` is authority.
- Never remove remote state manually or stop a process by name, port, path, or guessed PID.

## Proof and skip reporting

- Record the commit, Run ID, request hash, deadline, exact Session identity, manifest file hashes, capture type/method, and all cleanup facts.
- Keep private host configuration and resolved host details out of artifacts and public text.
- A failed read-only check is diagnosis, not proof and not setup authorization.
- A completed Scenario without verified returned evidence and known cleanup is not a pass.
- Report each unproved entry point with its exact failed command and prerequisite.

## Feature entry contract

Each feature file uses the public CLI, names its observable result, and lists conditions that invalidate proof. One entry point passing does not verify another.

## Features

- [Windows inspection](./windows-inspection.md) covers the bounded read-only target check.
- [Owned Windows setup](./windows-setup.md) covers runtime installation, preview, retries, removal, and legacy apply refusal.
- [Scenario run and evidence](./scenario-run.md) covers payload transfer, interactive launch, bounded drive, Evidence Bundle return, and known cleanup.
- [Recovery status and exact stop](./recovery-stop.md) covers reconnect observation and idempotent exact cleanup.
- [Linux host lifecycle](./linux-host.md) covers Linux readiness, explicit setup, real Scenario proof, and exact recovery.
- [Capture kinds and UI actions](./captures-ui.md) covers capture provenance, image inspection, UI capability prerequisites, and Linux refusals.
- [Named targets](./named-targets.md) covers local import, platform migration, named selection, and replacement-safe recovery.

For explicitly authorized Linux proof, follow [Linux Blender proof](../../../../docs/linux-proof.md). Exercise `plan` and `doctor` with viewport requirements. Require local refusal of Blender-window, desktop, and UI requests before transport. Linux uses its static user unit and reviewed runtime; Windows setup recipes do not apply.
