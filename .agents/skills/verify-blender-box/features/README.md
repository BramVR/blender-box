# Blender Box verification map

This map covers the public slice 0 CLI against an explicitly authorized owned Windows Blender host. Read the index first, then the feature recipe being proved.

## Baseline preconditions

- Build the client and Windows host binary from one exact checkout in a disposable `VERIFY_ROOT`.
- Set `BLENDER_BOX_TARGET` to an operator-supplied target outside the repository.
- Set `BLENDER_BOX_EXPECTED_HOSTNAME` and prove it before any setup write.
- Require an interactive Windows user, installed Blender, exact compatible `blendersessiond`, private SSH reachability, and no unknown Blender Session or Host Lock.
- Never expose or forward Blender's loopback MCP port.

## Driving conventions

- Run commands from the repository root.
- Treat stderr `RUN_ID=` as the pre-work recovery handle and stdout as one versioned result document.
- Use only public `windows check`, `windows setup`, `run`, `status`, and `stop` entry points.
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
- [Explicit Windows setup](./windows-setup.md) covers dry-run planning and authorized apply.
- [Scenario run and evidence](./scenario-run.md) covers payload transfer, interactive launch, bounded drive, Evidence Bundle return, and known cleanup.
- [Recovery status and exact stop](./recovery-stop.md) covers reconnect observation and idempotent exact cleanup.
