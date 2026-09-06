# Recovery status and exact stop

Recovery matches the supplied profile against the original user-local Run authority before contacting the host. It then validates the host-owned receipt and settles only the exact Run, request, hash, deadline, and accepted Session identity.

## Sub-features

- `status-reconnect` returns the durable receipt for one exact Run ID.
- `target-match` rejects changed target configuration before SSH, for both named and explicit-file selection.
- `authority-required` rejects missing or corrupt original Run authority before SSH.
- `session-pin` accepts a first exact Session only after validating the original full claim and rejects later changes.
- `stop-exact` resolves and stops only the receipt's exact Session identity.
- `stop-idempotent` accepts structured daemon absence after that exact Run-isolated Session has already stopped, while rejecting a replacement identity.
- `settle-idempotent` returns already-known cleanup without touching another Session.
- `starting-recovery` permits claim-only cleanup before Session publication.
- `launch-recovery` adopts a valid opaque identity from Run-isolated daemon state when Host Lock publication was interrupted.
- `startup-stop` uses an OS-released launch fence so settlement can interrupt daemon startup without claiming cleanup before identity publication.
- `deadline-state` records deadline-caused readiness, Scenario, and capture failures as `timed-out` receipts.
- `partial-cleanup` preserves Run ownership for retry, removes an ownership-free Run root only when it is otherwise empty and non-reparse, and absorbs transient Windows sharing violations inside the settlement deadline.

## How to get to it (user POV)

- Run `blender-box status --target TARGET --run RUN_ID --json` after reconnect.
- Run `blender-box stop --target TARGET --run RUN_ID --json` for exact cleanup.

## Driving it with blender-box

Preconditions:

- `VERIFY_RUN_ID` came from stderr or stdout of the same public `run` invocation.
- Keep the same user configuration root, including any `BLENDER_BOX_CONFIG_DIR` override, across Run and recovery processes.
- Do not substitute a Session name, PID, process pattern, or guessed ID.

- **Reconnect status.** Run `"$VERIFY_CLIENT" status --target "$BLENDER_BOX_TARGET" --run "$VERIFY_RUN_ID" --json | tee "$VERIFY_ROOT/status.json"`. Require the returned Run ID and exact Session ID to match the completed run.
- **Exact stop.** Run `"$VERIFY_CLIENT" stop --target "$BLENDER_BOX_TARGET" --run "$VERIFY_RUN_ID" --json | tee "$VERIFY_ROOT/stop.json"`. Require `status: settled` and all cleanup facts true.
- **Second view.** Run the same `status` command again and require the exact Session identity is unchanged and cleanup remains known.
- **Evidence retention.** Require `test -f "artifacts/blender-box/$VERIFY_RUN_ID/evidence.json"` after stop.

## Gotchas

- If the recovered claim, task name, request hash, deadline, or Session identity changed, stop must fail closed.
- A forgotten name fails locally. Identical original configuration under a new name or explicit file can recover; a replacement cannot inherit the Run's authority.
- A pre-upgrade Run without local authority cannot be adopted from a host reply.
- Do not remove a Host Lock or Run root manually after an error.
- A failed exact stop is not permission to kill Blender by process name or port.
