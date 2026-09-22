# Capture kinds and UI actions

Viewport, Blender-window, and desktop captures prove different surfaces. UI actions require a separate daemon capability.

## Captures

Start with the Scenario payload from `SKILL.md`. For Windows, use payload schema 2 and set the desired Scenario flags:

```json
{
  "capture_viewport": true,
  "capture_blender_window": true,
  "capture_desktop": true
}
```

Run a fresh `windows check` and `doctor --target TARGET --payload PAYLOAD --json`. Require passing readiness and support for every requested capture before `run`. Drive the Scenario with the usual private configuration, then perform exact `status` and idempotent `stop`.

Require the manifest to contain each requested type, matching Session identity, method, positive dimensions, and matching local/remote SHA-256. Inspect the actual images. An offscreen viewport does not establish window chrome. A Blender-window capture does not establish whether OS dialogs are present. A desktop image with blank content does not prove that Blender UI was visible, even when transfer and hashes pass. Keep private desktop content out of public proof.

Linux supports only viewport. A schema-2 window or desktop request must refuse locally before SSH.

## UI actions

Read `docs/architecture/0005-session-local-ui-actions.md` for the typed action contract. Payload schema 3 adds `scenario.ui_actions`. A minimal bounded batch is:

```json
{
  "schema_version": 1,
  "timeout_seconds": 15,
  "actions": [{"type": "key", "key": "F2"}]
}
```

Use a Scenario that selects a known object, request Blender-window evidence, and run `doctor` before launch. Windows requires the daemon's `blender-ui-events-v1` capability. If doctor reports it unsupported, retain that result and report UI actions as verified-unreachable due to the installed runtime. Do not infer support from a daemon version or ordinary Scenario success.

With a capable authorized runtime, require action receipts and before/after window evidence for the intended interaction, then exact cleanup. A capability refusal does not prove live action execution. Linux refuses UI actions before transport even if its daemon advertises that capability.
