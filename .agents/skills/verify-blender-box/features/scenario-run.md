# Scenario run and evidence

Run stages one declared payload, launches Blender through the interactive task, performs a bounded Scenario call, returns evidence, and records known cleanup.

## Sub-features

- `run-id` publishes the recovery Run ID before target or payload validation.
- `local-preflight` reserves the evidence destination without SSH; a local rejection does not attempt status recovery.
- `payload` transfers only declared bounded regular files and verifies them on Windows.
- `interactive-session` publishes one exact daemon Session identity, then waits for that same Session's process and socket health.
- `start-replay` repeats only the identical fenced start request while an `IgnoreNew` task has not published an identity.
- `long-call` carries the declared read timeout without dropping the Run deadline.
- `evidence` reserves the exclusive local destination before host inspection, returns non-empty hash-verified artifacts, and independently matches viewport PNG dimensions to declared provenance.
- `cleanup` reports exact Session stop, payload removal, Run-root removal, and lock release.

## How to get to it (user POV)

- Run `blender-box run --target TARGET --payload PAYLOAD --timeout 20m --json`.

## Driving it with blender-box

Preconditions:

- Doctor passed with `status: pass`.
- The Scenario and payload documents in `VERIFY_ROOT` were created exactly as in `SKILL.md`.

- **Run.** Execute the `run` command from `SKILL.md`, saving stdout and stderr separately.
- **Identity.** Require stderr's single `RUN_ID=` value to equal stdout `.run_id`; require `.session_id` to begin with `bss_`.
- **Completion.** Require `.state == "complete"` and all four cleanup booleans to be true.
- **Scenario result.** Require `artifacts/blender-box/$VERIFY_RUN_ID/result/scenario-result.json` to name `BlenderBoxSlice0Cube` with schema v1 and pass status.
- **Viewport.** Require the manifest to declare a `viewport` capture with a named capture method and positive dimensions, then inspect the returned PNG when visual content matters.
- **Hashes.** Run the manifest hash loop in `SKILL.md` and require every local SHA-256 to match.

## Gotchas

- `RUN_ID=` is stderr progress; stdout remains one JSON document.
- A viewport capture does not prove Blender window chrome or the Windows desktop.
- Never treat a Session name as stop authority.
- Never reuse a Run ID whose durable receipt became terminal or lost its Host Lock.
- Evidence directory publication is exclusive; reuse of the same Run directory fails closed.
