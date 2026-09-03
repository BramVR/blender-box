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

Slice 0 uses Design C. After proving the daemon path is trusted, `windows check` runs `blendersessiond capabilities --require blender-box-v1 --require-capability typed-call-error-reason --require-capability windows-setup-owner-v1`. Those capabilities mean the daemon returns opaque Session identities, requires them for call and stop, accepts bounded call read timeouts, types a read-timeout failure independently of process exit prose, and supports the fenced Windows setup-owner contract. Explicit setup applies the daemon ACL, runs the same probe, and registers the Scheduled Task only after it passes.

The probe has a ten-second process deadline and gives stdout and stderr distinct spellings of the Windows null device, so output never enters PowerShell or client memory. It touches the process handle before waiting because Windows PowerShell otherwise may not retain the exit code for a redirected `Start-Process`. Failure is readiness failure; it never falls back to an unfenced call or stop.

## Consequences

- An old daemon is rejected before Blender launch.
- Setup still requires the operator to provision `blendersessiond`; it does not deploy or upgrade it.
- Changing the required daemon contract needs a new named capability version and coordinated producer/consumer updates.
