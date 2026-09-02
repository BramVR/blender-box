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

Design B probes the existing command help surface. It runs no Blender lifecycle command and checks the exact call and stop options Blender Box will later require.

## Decision

Slice 0 uses Design B. After proving the daemon path is trusted, `windows check` runs bounded `call --help` and `stop --help` subprocesses and requires `--expect-session-id` on both relevant operations plus `--read-timeout` on call. Explicit setup applies the daemon ACL, runs the same probe, and registers the Scheduled Task only after it passes.

The probe has a ten-second process deadline and rejects more than 64 KiB of combined help output. Failure is readiness failure; it never falls back to an unfenced call or stop.

## Consequences

- An old daemon is rejected before Blender launch.
- Setup still requires the operator to provision `blendersessiond`; it does not deploy or upgrade it.
- A future daemon may replace help-text probing with a versioned machine-readable capability command, but Blender Box must keep fail-closed exact identity and timeout checks through that migration.
