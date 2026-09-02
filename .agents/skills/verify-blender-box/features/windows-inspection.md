# Windows inspection

Windows inspection checks whether the declared host is ready without changing remote state.

## Sub-features

- `check-contract` returns versioned JSON with every required check and requires the non-launching `blendersessiond` `blender-box-v1` capability contract.
- `check-identity` validates SSH and interactive-user SIDs.
- `check-authority` validates path ACLs and exact Scheduled Task authority.
- `check-no-write` performs no setup, launch, or cleanup mutation.

## How to get to it (user POV)

- Run `blender-box windows check --target TARGET --json`.

## Driving it with blender-box

Preconditions:

- `VERIFY_CLIENT` is the exact built CLI.
- `BLENDER_BOX_TARGET` is a valid operator-supplied target.

- **Inspect.** Run `"$VERIFY_CLIENT" windows check --target "$BLENDER_BOX_TARGET" --json | tee "$VERIFY_ROOT/check.json"`. Exit `0` means every required check passed; exit `1` with valid JSON means the host is not ready.
- **Validate contract.** Run `jq -e '.schema_version == 1 and (.checks | length == 10) and ([.checks[].id] | unique | length == 10)' "$VERIFY_ROOT/check.json"`.
- **Confirm Blender check.** Run `jq -e '[.checks[] | select(.id == "blender.executable")] | length == 1' "$VERIFY_ROOT/check.json"`.

## Gotchas

- Check does not install files, register a task, launch Blender, or clear a stale lock.
- A private target is input, never a fixture or proof artifact.
- Do not infer the hostname from the SSH alias; verify the expected computer name separately before setup.
