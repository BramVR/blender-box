# Recovery status and exact stop

Recovery reads the host-owned receipt after reconnect and settles only the exact Run, request, hash, deadline, and Session authority stored there.

## Sub-features

- `status-reconnect` returns the durable receipt for one exact Run ID.
- `stop-exact` resolves and stops only the receipt's exact Session identity.
- `stop-idempotent` returns already-known cleanup without touching another Session.
- `starting-recovery` permits claim-only cleanup before Session publication.
- `partial-cleanup` preserves Run ownership for retry and absorbs transient Windows sharing violations inside the settlement deadline.

## How to get to it (user POV)

- Run `blender-box status --target TARGET --run RUN_ID --json` after reconnect.
- Run `blender-box stop --target TARGET --run RUN_ID --json` for exact cleanup.

## Driving it with blender-box

Preconditions:

- `VERIFY_RUN_ID` came from stderr or stdout of the same public `run` invocation.
- Do not substitute a Session name, PID, process pattern, or guessed ID.

- **Reconnect status.** Run `"$VERIFY_CLIENT" status --target "$BLENDER_BOX_TARGET" --run "$VERIFY_RUN_ID" --json | tee "$VERIFY_ROOT/status.json"`. Require the returned Run ID and exact Session ID to match the completed run.
- **Exact stop.** Run `"$VERIFY_CLIENT" stop --target "$BLENDER_BOX_TARGET" --run "$VERIFY_RUN_ID" --json | tee "$VERIFY_ROOT/stop.json"`. Require `status: settled` and all cleanup facts true.
- **Second view.** Run the same `status` command again and require the exact Session identity is unchanged and cleanup remains known.
- **Evidence retention.** Require `test -f "artifacts/blender-box/$VERIFY_RUN_ID/evidence.json"` after stop.

## Gotchas

- If the recovered claim, task name, request hash, deadline, or Session identity changed, stop must fail closed.
- Do not remove a Host Lock or Run root manually after an error.
- A failed exact stop is not permission to kill Blender by process name or port.
