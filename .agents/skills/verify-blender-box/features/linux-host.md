# Linux host lifecycle

Linux uses an owned Ubuntu 24.04 GNOME Xorg desktop and a static systemd user service. The shared Run, evidence, and exact recovery contracts apply.

## Preconditions

- Read `docs/linux.md`, `docs/linux-proof.md`, and ADR 0006 before setup.
- Require the declared SSH UID to own one active local GNOME Xorg session, systemd 255 with cgroup v2, Blender 5.2.0, and the reviewed copied CPython 3.12 runtime.
- The daemon package must match the compiled manifest and remain read-only. Setup does not install or repair the runtime or desktop.
- The static service must have the declared bytes and effective `UMask=0077`. An inactive service and absent Host Lock are prerequisites for a new Run.
- Use the existing operator-owned Host Lock root. A different root cannot bypass another Run.

## Drive

Use a clean committed candidate and private operator document with exact host, fixture, launch, and any separately authorized setup fields. Follow the document schema in `docs/linux-proof.md`.

```sh
python3 scripts/linux_blender_proof.py baseline \
  --candidate "$CANDIDATE_SHA" \
  --candidate-checkout "$CANDIDATE_CHECKOUT" \
  --operator-config "$BLENDER_BOX_PROOF_CONFIG" \
  --output "$PROOF_OUTPUT" \
  --execution local
```

The runner builds exact binaries, verifies the setup plan and authorized apply, requires all six `linux check` results, runs the cube Scenario, validates returned evidence, and reconnects through fresh `status`, `stop`, and final `status` processes. Require all six outcomes and all four cleanup facts in `public/outcome.json`. Inspect the viewport and matching remote/local hashes.

Before another drive after failure, repeat readiness. Preserve the original target, private configuration, journal, Run claim, and Session pin whenever cleanup is unknown. Use exact public recovery commands; never reset state or stop by process name. A failed service needs operator inspection even after exact settlement.

## Limits

Linux supports viewport capture. Public `plan`, `doctor`, and `run` refuse Blender-window, desktop, and UI action requests before transport. Use valid payloads from the capture/UI recipe to verify those refusals.

A baseline pass does not prove deliberate SSH interruption, desktop logout, service crash, or kept Sessions. Hosted mode currently refuses with `hosted-recovery-retention-unavailable`; a local pass does not satisfy the hosted acceptance criterion.
