---
name: verify-blender-box
description: "Launch and verify the Blender Box CLI against an explicitly authorized owned Windows Blender host."
---

# Verify Blender Box

Use this skill for real user-facing proof of the Blender Box CLI. The host is shared operator state: require explicit authorization for setup or Blender launch, never expose Blender's loopback MCP port, and never stop a process except through the exact Run and Session identities recovered by Blender Box.

## Launch

From the repository root, use one isolated local scratch directory and build both client and Windows host binaries from the exact checkout:

```sh
export VERIFY_TMPDIR="${TMPDIR:-/tmp}"
export VERIFY_ROOT="$(mktemp -d "${VERIFY_TMPDIR%/}/blender-box-verify.XXXXXX")"
export VERIFY_CLIENT="$VERIFY_ROOT/blender-box"
export VERIFY_HOST_BINARY="$VERIFY_ROOT/blender-box.exe"
go build -o "$VERIFY_CLIENT" ./cmd/blender-box
GOOS=windows GOARCH=amd64 go build -o "$VERIFY_HOST_BINARY" ./cmd/blender-box
git rev-parse HEAD | tee "$VERIFY_ROOT/commit.txt"
```

`BLENDER_BOX_TARGET` must name an operator-supplied, non-secret target JSON outside the repository. `BLENDER_BOX_EXPECTED_HOSTNAME` must be the exact expected Windows computer name. Keep both values and all resolved host details out of committed files and public proof.

## Doctor

Require the input files, verify the hostname before any write, inspect Blender availability, and run the complete read-only target check:

```sh
test -x "$VERIFY_CLIENT"
test -f "$VERIFY_HOST_BINARY"
test -f "$BLENDER_BOX_TARGET"
test -n "$BLENDER_BOX_EXPECTED_HOSTNAME"
export VERIFY_SSH_ALIAS="$(jq -er '.ssh_alias' "$BLENDER_BOX_TARGET")"
export VERIFY_HOSTNAME_OUTPUT="$(ssh -o RequestTTY=no -o RemoteCommand=none -- "$VERIFY_SSH_ALIAS" powershell.exe -NoLogo -NoProfile -NonInteractive -Command '$env:COMPUTERNAME')"
export VERIFY_ACTUAL_HOSTNAME="$(printf '%s' "$VERIFY_HOSTNAME_OUTPUT" | tr -d '\r')"
test "$(printf '%s' "$VERIFY_ACTUAL_HOSTNAME" | wc -l | tr -d '[:space:]')" = "0"
test -n "$VERIFY_ACTUAL_HOSTNAME"
test "$(printf '%s' "$VERIFY_ACTUAL_HOSTNAME" | tr '[:lower:]' '[:upper:]')" = "$(printf '%s' "$BLENDER_BOX_EXPECTED_HOSTNAME" | tr '[:lower:]' '[:upper:]')"
"$VERIFY_CLIENT" windows check --target "$BLENDER_BOX_TARGET" --json | tee "$VERIFY_ROOT/check.json"
jq -e '.schema_version == 1 and (.status == "pass" or .status == "fail") and ([.checks[] | select(.id == "blender.executable" and (.passed | type == "boolean"))] | length == 1)' "$VERIFY_ROOT/check.json"
```

Require `status: pass` before `run`. A failed check is useful read-only diagnosis, but it is not permission to apply setup. Confirm no unknown Blender process or unknown Host Lock is active before continuing; do not stop either.

## Drive

Create one bounded Scenario in scratch, then drive it through the public CLI:

```sh
cat > "$VERIFY_ROOT/scenario.py" <<'PY'
import json
import bpy

bpy.ops.object.select_all(action="SELECT")
bpy.ops.object.delete(use_global=False)
bpy.ops.mesh.primitive_cube_add(location=(0.0, 0.0, 0.0))
bpy.context.active_object.name = "BlenderBoxSlice0Cube"
print(json.dumps({"schema_version": 1, "status": "pass", "object": "BlenderBoxSlice0Cube"}, separators=(",", ":")))
PY
cat > "$VERIFY_ROOT/payload.json" <<'JSON'
{
  "schema_version": 1,
  "files": [
    {"source": "scenario.py", "destination": "scenario.py"}
  ],
  "scenario": {
    "script": "scenario.py",
    "read_timeout_seconds": 600,
    "capture_viewport": true
  }
}
JSON
"$VERIFY_CLIENT" run --target "$BLENDER_BOX_TARGET" --payload "$VERIFY_ROOT/payload.json" --timeout 20m --json > "$VERIFY_ROOT/run.json" 2> "$VERIFY_ROOT/run.stderr"
export VERIFY_RUN_ID="$(jq -er '.run_id' "$VERIFY_ROOT/run.json")"
test "$(sed -n 's/^RUN_ID=//p' "$VERIFY_ROOT/run.stderr")" = "$VERIFY_RUN_ID"
jq -e '.schema_version == 1 and .state == "complete" and (.session_id | startswith("bss_")) and .cleanup.session_stopped and .cleanup.payload_removed and .cleanup.run_root_removed and .cleanup.lock_released' "$VERIFY_ROOT/run.json"
"$VERIFY_CLIENT" status --target "$BLENDER_BOX_TARGET" --run "$VERIFY_RUN_ID" --json | tee "$VERIFY_ROOT/status.json"
jq -e --arg run "$VERIFY_RUN_ID" '.schema_version == 1 and .run_id == $run and .state == "complete" and .cleanup.lock_released' "$VERIFY_ROOT/status.json"
```

Use `status` as the second user-facing view after reconnect. Keep the original target and local configuration root. `status` and `stop` compare host-owned receipts with the original local request claim and Session pin before accepting recovery authority.

## Evidence

The retained Evidence Bundle is `artifacts/blender-box/$VERIFY_RUN_ID`. It must contain `evidence.json`, `manifest.json`, `result/scenario-result.json`, and `screenshots/viewport.png` for this Scenario.

```sh
export VERIFY_EVIDENCE="artifacts/blender-box/$VERIFY_RUN_ID"
test -f "$VERIFY_EVIDENCE/evidence.json"
test -f "$VERIFY_EVIDENCE/manifest.json"
jq -e '.schema_version == 1 and .status == "pass" and .object == "BlenderBoxSlice0Cube"' "$VERIFY_EVIDENCE/result/scenario-result.json"
jq -e '.schema_version == 1 and ([.files[] | select(.type == "viewport" and (.capture_method == "offscreen" or .capture_method == "window_grab") and .width > 0 and .height > 0)] | length == 1)' "$VERIFY_EVIDENCE/manifest.json"
while IFS=$'\t' read -r relative expected; do test "$(shasum -a 256 "$VERIFY_EVIDENCE/$relative" | awk '{print $1}')" = "$expected"; done < <(jq -r '.files[] | [.path, .sha256] | @tsv' "$VERIFY_EVIDENCE/manifest.json")
```

Record only the tested commit, Run ID, exact Session identity, declared evidence hashes/capture provenance, and cleanup booleans. Do not publish the target document, hostname, users, addresses, paths, SSH details, or credentials.

## Cleanup

Prove idempotent recovery cleanup without touching an unknown process, retain evidence, then remove only the exact local scratch directory:

```sh
"$VERIFY_CLIENT" stop --target "$BLENDER_BOX_TARGET" --run "$VERIFY_RUN_ID" --json | tee "$VERIFY_ROOT/stop.json"
jq -e --arg run "$VERIFY_RUN_ID" '.schema_version == 1 and .run_id == $run and .status == "settled" and .cleanup.session_stopped and .cleanup.payload_removed and .cleanup.run_root_removed and .cleanup.lock_released' "$VERIFY_ROOT/stop.json"
test -f "$VERIFY_EVIDENCE/evidence.json"
case "$VERIFY_ROOT" in "${VERIFY_TMPDIR%/}"/blender-box-verify.*) rm -rf -- "$VERIFY_ROOT" ;; *) echo "refusing unexpected cleanup root" >&2; exit 1 ;; esac
test ! -e "$VERIFY_ROOT"
test -f "$VERIFY_EVIDENCE/evidence.json"
git status --short --untracked-files=all
```

Artifacts are ignored product evidence, not scratch. Keep them until proof is reported.

## Helpers

For repeatable onboarding proof, use `scripts/onboarding_proof.py baseline` or `scripts/onboarding_proof.py named-target` with the private operator configuration described in `docs/windows-onboarding-proof.md`. Both drive the public CLI and share evidence and recovery assertions. They do not grant setup, fixture reset, or hosted dispatch permission. Require actual hosted `Windows onboarding proof` results for both `baseline` and `named-target`; local or skipped jobs do not satisfy them. Read `features/named-targets.md` for target-specific acceptance.

Hosted execution currently fails preflight until private original Run authority can survive an ephemeral controller's loss. Keep this blocker visible; public outcome uploads cannot restore the private journal.

For owned runtime installation and removal, read `features/windows-setup.md`. Use `scripts/onboarding_proof.py host-install` only with its separately bound dedicated fixture authorization and verified external bootstrap/bundle. Require the actual `host-install` hosted job; its retention preflight remains blocked. Legacy `windows setup --apply` refuses unowned mutation before SSH.

For focused manual proof, drive `blender-box` directly using the recipe above. Use the public `status`/`stop` commands for host recovery and cleanup. Do not infer fixture ownership from a path or task name.

Read `features/README.md` and the matching feature file before exercising a user path.
