# Explicit Windows setup

Windows setup previews a bounded host binary install by default and applies only the declared file, ACL, and interactive Scheduled Task under explicit authorization.

## Sub-features

- `setup-plan` hashes and sizes the host binary without SSH or remote writes.
- `setup-apply` stages the bounded binary and hash-verified setup program over SCP, then registers the fixed task.
- `setup-postcheck` proves the applied state through the read-only check.

## How to get to it (user POV)

- Run `blender-box windows setup --target TARGET --host-binary EXE --json` for a plan.
- Add `--apply` only after explicit host-write authorization and hostname verification.

## Driving it with blender-box

Preconditions:

- `VERIFY_HOST_BINARY` is the Windows build from the tested commit.
- The declared compatible `blendersessiond` and Blender executables already exist.
- The exact hostname check in `SKILL.md` passed and the operator authorized setup.

- **Plan.** Run `"$VERIFY_CLIENT" windows setup --target "$BLENDER_BOX_TARGET" --host-binary "$VERIFY_HOST_BINARY" --json | tee "$VERIFY_ROOT/setup-plan.json"`. Require `jq -e '.schema_version == 1 and .status == "plan" and (.applied | not) and .host_size > 0 and (.host_sha256 | length == 64)' "$VERIFY_ROOT/setup-plan.json"`.
- **Apply.** Run `"$VERIFY_CLIENT" windows setup --target "$BLENDER_BOX_TARGET" --host-binary "$VERIFY_HOST_BINARY" --apply --json | tee "$VERIFY_ROOT/setup-apply.json"`. Require the same size and SHA-256 as the plan plus `status: applied`.
- **Second view.** Run `"$VERIFY_CLIENT" windows check --target "$BLENDER_BOX_TARGET" --json | tee "$VERIFY_ROOT/check-after-setup.json"` and require `jq -e '.schema_version == 1 and .status == "pass"' "$VERIFY_ROOT/check-after-setup.json"`.

## Gotchas

- `--apply` changes the declared Blender Box work root, managed executable ACLs, and exact Scheduled Task. It does not install Blender or `blendersessiond`.
- A task-local Python virtual environment is compatible when its `blendersessiond` launcher resolves without ambient `PYTHONPATH`.
- Never apply to a host identified only by an alias.
- Setup does not launch Blender and does not authorize stopping an existing process.
