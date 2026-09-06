---
summary: Linux desktop launch, reviewed daemon imports, and shared Run authority.
read_when:
  - Changing Linux target validation, systemd launch, runtime provenance, or setup.
  - Extending host requests, daemon bindings, or POSIX filesystem authority.
---

# Linux host boundary

This decision was numbered 0004 on the Linux branch. It is now 0006 to preserve the existing Windows setup-owner and UI-action decision numbers.

## Decision

Linux uses the existing seven-method `HostAdapter` and host Run state machine. The client selects a concrete adapter after target resolution. PlanResult, HostRequirements, and HostInspection remain shared typed contracts. Linux inspection reports viewport support after all required Linux readiness checks pass. `orchestrator.New` and the local original-target authority records remain unchanged.

The intended platform is Ubuntu 24.04 LTS with GNOME on Xorg, systemd 255, unified cgroup v2, CPython 3.12, and Blender 5.2.0. This is a support contract, not evidence that any operator host meets it. Local fake-boundary tests pass. Native Linux, Blender, and hosted proof remain separate acceptance requirements.

A fixed desktop and reviewed runtime make the authority check concrete. A transient-unit protocol, alternate import mechanism, or generic host framework would add state without proving another supported configuration.

## Wire compatibility

Target version 2 contains exactly one Windows or Linux body. Linux configuration lives in `internal/linuxtarget`. It includes the UID and explicit passwd home so a local setup preview can name the exact unit destination without contacting the host. Windows version 1 input still normalizes to the same version 2 bytes and fingerprint.

Windows `RequestBody` and `SettleRequest` retain schema 1 and their exact JSON encoding. Linux uses schema 2. The request hash includes `LinuxLaunch`, with the desktop, UID, and `DaemonRuntime`. Its broker executable must equal the runtime's Python executable. Settlement derives its runtime from the authority-matched original target, never from writable Run state.

Host Start, ExecutePending, and Settle reject opposite-platform input before mutation or daemon invocation. Every daemon Start, Ready, Recover, Call, and Stop receives one `DaemonBinding`. Host Lock claims and Session pins keep their existing authority semantics. Payload schema 2 viewport evidence uses the shared typed provenance contract. Linux refuses Blender-window capture, desktop capture, and UI action batches before a Host Lock is acquired. Direct host Start and ExecutePending validate the same restriction before mutation or daemon launch.

## Desktop service lifetime

Explicit setup writes `Home/.config/systemd/user/UnitName`. The static service uses:

```ini
[Service]
Type=exec
ExitType=cgroup
RemainAfterExit=no
Restart=no
KillMode=process
```

Its exact `ExecStart` invokes the declared host executable with `host run-request --state-root WorkRoot`. Fixed environment entries provide Home, Display, Xauthority, and the UID-derived runtime directory and session bus. Setup performs no enablement or automatic restart. There is no `ExecStop`, `PartOf`, or product use of `systemctl stop`, `restart`, or `kill`.

The unit remains active while descendants remain. That lifetime prevents another Run from silently starting over an unresolved Session. It is not cleanup authority. Only the daemon's exact Session identity authorizes process stop.

`TaskLauncher.Prepare` runs under the existing operation lock before a fresh request, pending request, or starting receipt is published. Linux preparation verifies desktop and unit configuration and requires an inactive unit. It refuses immediately if a prior lifecycle remains active. Windows preparation is a no-op. `LaunchRequest` carries the already-validated root and complete request to both platforms. Windows keeps the same `schtasks.exe /Run /TN` arguments.

An identical starting request can replay the launch after ambiguous SSH or client failure. It was already prepared before publication. Linux validates the unit again and lets an active identical service continue. After host-process death, exact settlement can recover the daemon identity, but the Scenario does not resume. Failed units require operator inspection and an explicit failed-state reset after exact cleanup.

Readiness verifies one active local GNOME X11 logind session for the SSH UID, its seat and display, its Xauthority, and a real Xorg process in that exact session scope. GDM's `-displayfd` launch is supported. Wayland, virtual displays, remote sessions, and ambiguity refuse. The host entry point also checks its configured static service cgroup before daemon Start. Status and settlement remain available after logout.

The effective unit check compares file bytes, executable, root, environment, aliases, drop-ins, and lifecycle properties. It accepts systemd 255's default user-service dependencies on `basic.target` and `app.slice`, with `Slice=app.slice`. It rejects foreign dependencies and configuration. The chosen cgroup lifetime requires unified cgroup v2.

## Reviewed runtime layout

`internal/linuxruntime/reviewed-daemon-manifest.json` contains trusted metadata for all 20 package files. It pins base commit `6d40e40376897b09c18fc13c60296d37c5bef2ba`, UI patch SHA-256 `73b7b2433dae44e4032a50fa619e9e23addbd597b01043ecf74ffa6c92b87ebc`, and correction SHA-256 `9a54bfb9bd0b44690acaed32da52cca3f285781cdaa481c5c089576dc7013721`. No daemon source is vendored. The correction's existing proof level is `PASS_SHARED_POSIX_FAKE`, without native Linux or upstream integration claims.

The dedicated venv has this bounded layout:

- A UID-owned, owner-only root and a regular `pyvenv.cfg` for system CPython 3.12, with `home=/usr/bin`, `executable=/usr/bin/python3.12`, and disabled system site packages.
- `bin/python3`, plus optional regular `bin/python` and `bin/python3.12` copies. Each accepted executable matches the trusted system interpreter's bytes.
- `lib/python3.12/site-packages/blendersessiond`, containing exactly the compiled manifest's package files, including vendor data.
- An optional empty `include` directory and at most one bounded `blendersessiond-*.dist-info` directory. Only the enumerated metadata filenames are permitted there.

A stock `venv --copies` directory commonly contains activation scripts and a `lib64` symlink. Those entries are rejected. Provisioning a sealed runtime is an external prerequisite. Product setup never removes venv files to make an installation pass.

Verification rejects symlinks, unexpected packages, `.pth` files, customization modules, bytecode, unsafe ownership or permissions, and excessive directory entries. It validates physical paths and `pyvenv.cfg` before a bounded interpreter-prefix and import-origin probe. Trusted Ubuntu standard libraries remain an operating-system prerequisite.

Each daemon operation repeats provenance verification. Top-level invocation uses the selected Python with `-I -B -m blendersessiond`. Its environment replaces inherited process variables and explicitly carries `PYTHONNOUSERSITE=1`, `PYTHONSAFEPATH=1`, and `PYTHONDONTWRITEBYTECODE=1`. The two recursive `sys.executable -m blendersessiond.posix_launcher` calls inherit those controls. Top-level `-I` alone would not protect them.

The current wheel fails the package hashes. Capability checks still require the existing `blender-box-v1` contract and typed call errors. No new public daemon capability is invented. Runtime drift during settlement reports unresolved cleanup rather than selecting another interpreter.

## Setup and filesystem authority

Plan mode is local and reports exact binary size and hash, unit bytes and hash, destinations, and unverified prerequisites. Apply streams bounded input to a system-Python `-I -S -B` standard-library bootstrap. It installs only the managed binary, private state, and static unit.

Under the shared operation lock, apply rejects a Host Lock, an active or transitioning unit, foreign effective configuration, and unrecognized artifacts. A scoped ownership receipt records the actual recognized installed hashes and pending replacements. The binary is published before manager reload. Successful setup requires effective unit verification after reload.

Complete interrupted temporary files are flushed before publication. A complete initial ownership temporary can recover only with matching identity and no unexpected accompanying artifacts. Partial or mismatched temporary files refuse for inspection. Recognized bytes from an interrupted candidate remain recorded when a later candidate replaces them.

Physical paths reject symlinks and untrusted writers. Private managed roots and lock files belong to the current UID. A root-owned sticky ancestor can protect an existing private child. New directory entries and authority publication are flushed through their parent hierarchy. POSIX flock opens use no-follow and regular-file, owner, and mode checks. Cleanup retains ownership until other Run entries are gone and rejects unsafe descendants. This does not claim protection from an actively hostile process under the same UID.

## Verification

Default tests use the real orchestrator, Linux adapter, and host service with fake SSH, desktop service, and daemon boundaries. They cover returned PNG hashes and provenance, dropped SSH, startup failure, replacement identity, and repeated exact stop. A real local Python subprocess test exercises both recursive imports with a decoy working directory. Setup tests cover bounded input and output, active-unit refusal, temporary-file durability, and interrupted replacement.

These tests establish local contract behavior. They do not establish native systemd lifetime, desktop logout behavior, a real Blender Scenario, or hosted recovery retention. The [Linux proof workflow](../linux-proof.md) retains the unconditional hosted-retention preflight refusal until private durable authority and recovery are configured.
