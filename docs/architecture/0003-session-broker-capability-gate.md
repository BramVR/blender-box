---
summary: Windows readiness proves the exact blendersessiond CLI contract before Blender can launch.
read_when:
  - Changing blendersessiond invocation, Windows setup, readiness checks, or Session fencing.
---

# Session broker capability gate

## Status

Accepted for slice 0.

## Problem

Blender Box requires `blendersessiond` to return an opaque Session identity, require that identity for call and stop, and accept a bounded call read timeout. The package version did not change when these contracts landed, so file presence, ACL checks, or version comparison cannot distinguish a compatible daemon from one that may launch Blender and then fail identity-safe cleanup.

## Considered designs

Design A pins a package version. It is small, but it cannot describe the current compatibility boundary because compatible and incompatible builds share that version.

Design B probes the existing command help surface. It runs no Blender lifecycle command, but Python argument parsing exits on `--help` before rejecting unknown options. Capturing arbitrary help text also adds a hostile-output boundary to setup and inspection.

Design C gives `blendersessiond` one versioned capability command with a required contract name. A known command and contract return zero without reading or changing Session state; an older daemon or unknown contract returns nonzero.

## Decision

Slice 0 uses Design C. After proving the daemon path is trusted, `windows check` runs `blendersessiond capabilities --require blender-box-v1 --require-capability typed-call-error-reason`. Those capabilities mean the daemon returns opaque Session identities, requires them for call and stop, accepts bounded call read timeouts, and types a read-timeout failure independently of process exit prose. Owned installation applies the daemon ACL, runs the same probe, and registers its marked Scheduled Task only after it passes. The retired SSH setup-owner capability is no longer a runtime readiness requirement; an existing legacy setup-owner tree must still pass the trusted-state scan.

Readiness also scans owned setup execution journals and rejects a pending setup fence. `doctor` therefore cannot report a host ready while installer process cleanup or task-mutation completion remains unresolved.

Capture-aware `doctor` keeps that daemon gate, then asks an upgraded `blender-box` host binary for its built-in capture implementations. The host command proves the installed binary contains the schema 2, Blender-window, and desktop paths; it does not claim a live capture. Schema 1 viewport-only and no-capture Payloads retain the original inspection path so a client update does not make the existing workflow depend on a new host command. Every schema 2 Payload requires the upgraded host binary and fails before staging when it is absent.

The read-only readiness probe has a ten-second process deadline and gives stdout and stderr distinct spellings of the Windows null device, so output never enters PowerShell or client memory. It touches the process handle before waiting because Windows PowerShell otherwise may not retain the exit code for a redirected `Start-Process`. Owned installation uses its bounded native process runner for the same capability command and checks that private Python can resolve daemon child modules. Failure never falls back to an unfenced call or stop.

## Consequences

- An old daemon is rejected before Blender launch.
- [Owned setup](0007-windows-installation-ownership.md) provisions a pinned private daemon runtime and runs this capability contract. It does not infer compatibility from the wheel version or upgrade an existing unowned daemon.
- Changing the required daemon contract needs a new named capability version and coordinated producer/consumer updates.
