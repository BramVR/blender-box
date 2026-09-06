---
summary: Bounded UI actions target one exact Blender Session and retain a durable delivery journal.
read_when:
  - Changing UI action parsing, event delivery, window identity, journal recovery, or failure evidence.
---

# Session-local UI actions

Payload schema 3 requires one `scenario.ui_actions` batch. Scenarios without UI actions use schema 1 or 2. The batch and its delivery journal use `schema_version: 1`. Existing payload schemas, request envelopes, and capture contracts keep their original behavior.

The action model is a closed union of `click`, `key` with optional modifiers, and `text`. Limits apply at both payload parsing and staged-manifest validation. The immutable request hash includes every action. Plan reports the action count, timeout, required capability, and capture paths without returning entered text. `expected_evidence` is an inventory of evidence types, with each type listed once. `captures` lists the concrete files, so a UI batch can declare two Blender-window paths under one evidence type.

## Delivery boundary

`UIActor` owns the platform boundary. The host holds the operation lock while it verifies the complete Run claim and exact Session, persists one `pending` action, and waits for its bounded acknowledgement. The host releases that lock between actions so settlement can proceed. Each action has at most five seconds within the batch and Run deadlines.

The runtime requires daemon capability `blender-ui-events-v1` and starts declared UI Sessions with `--enable-ui-events`. It also checks that the selected Blender executable advertises `--enable-event-simulate`. That Blender mode disables real physical mouse and keyboard input in the Session. Ordinary Sessions retain the original launch arguments. The start response must confirm `enable_ui_events` for an opted-in Session.

The built-in Python program enters Blender only through the daemon's exact `--expect-session-id` call. It binds the first action to the current process creation time, exactly one visible top-level native window, and exactly one Blender window. A native window property detects destroyed and reused handles. Later actions require that same binding, foreground window, and matching native and Blender client dimensions. Multiple windows, unsupported coordinates, and focus loss fail closed.

All events target the pinned `bpy.types.Window.event_simulate` instance. The program neither moves the operating-system cursor nor changes global keyboard, mouse, or clipboard state. Client coordinates use a top-left origin and convert to Blender's bottom-left origin. Key and text events retain the last click position. When a batch starts with a key or text action, the program samples the current cursor inside the client area without moving it.

Text lowers to an F24 press containing one Unicode scalar and an F24 release without a Unicode field. Public keys exclude F24. Every action balances its own keys and modifiers. On partial failure, cleanup releases only through the pinned Blender window. Absolute deadlines are checked inside Blender before each event and acknowledgement, so an abandoned daemon request cannot keep injecting after its action budget.

## Acknowledgement and evidence

An enqueue response does not prove a visible effect. The program registers a Blender application timer that acknowledges on its second callback traversal. Blender processes window events between those traversals. The exact Session receives one daemon call. Its callback atomically publishes a bounded acknowledgement in a host-created private directory under the Run root. The envelope binds the complete Run claim, exact Session, action index, and random nonce. The host accepts it only after a validated pending response and before the action deadline, then admits the next action or requests the after image. Local file polling avoids a second daemon CLI launch and its repeated Session health inspection. Windows create-once rename prevents receipt replacement; Blender never creates the parent directory. The directory remains until exact Run cleanup, and interrupted delivery is never replayed. `queued` means this delivery barrier passed. It does not assert that a specific control accepted the input or that a Scenario's semantic goal succeeded.

The journal contains a contiguous prefix of `queued` receipts and at most one final `pending`, `rejected`, or `uncertain` receipt. Receipts record the index, action kind, exact Session, client dimensions when known, event count, and a bounded error code. They contain no entered text, text prefix, or text hash. Observation rejects rewritten history. Task restart and settlement turn a durable `pending` action into `uncertain` and never replay it.

For a UI batch, `capture_blender_window: true` requests `screenshots/blender-window-before-actions.png` after the preparation script and `screenshots/blender-window-after-actions.png` after all acknowledgements. `result/ui-actions.json` records the terminal journal. A failed Run returns the journal and available captures before exact cleanup. If the client was cancelled, recovery fetches available evidence before settlement and can reconstruct the final journal from the settled host receipt only when its canonical bytes match the host manifest's size and SHA-256. Bundle metadata marks that path with `ui_journal_recovered_from_receipt: true`.

The input payload itself contains text, and screenshots can show text. Receipt redaction does not make those artifacts private.

## Verification boundary

The default suite executes the actual embedded Python program against deterministic fake Blender and Win32 interfaces. It covers pointer conversion, Unicode lowering, the two-pass acknowledgement, focus changes, handle reuse, deadlines, and local release. Go tests cover schema limits, request hashing, capability gates, durable admission, failure journals, prefix validation, cancellation recovery, and cleanup. Real GUI proof remains opt-in and verifies visible results separately from the delivery receipt.
