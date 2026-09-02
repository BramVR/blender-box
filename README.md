# blender-box

Remote Blender GUI Scenario runner for owned Windows hosts.

Blender Box runs from a developer checkout, reaches Windows over SSH, stages a declared Run Payload, starts Blender in the logged-in desktop through an interactive Scheduled Task, drives the host-local `blendersessiond`, and returns structured and visual evidence.

Tailscale currently provides private host reachability through the configured SSH alias. Blender's MCP add-on remains bound to Windows loopback.

## Status

Slice 0 implementation is in progress. The public CLI currently provides a read-only Windows target check. Run orchestration, setup apply, Host Locks, evidence, and exact stop are not available yet.

## Windows target check

Create a non-secret target file with absolute Windows paths and a safe SSH config alias:

```json
{
  "schema_version": 1,
  "ssh_alias": "owned-windows-host",
  "work_root": "C:\\BlenderBox",
  "interactive_user": "HOST\\operator",
  "task_name": "BlenderBoxHost",
  "blender_executable": "C:\\Program Files\\Blender Foundation\\Blender\\blender.exe",
  "session_broker_executable": "C:\\BlenderBox\\bin\\blendersessiond.exe",
  "host_executable": "C:\\BlenderBox\\bin\\blender-box.exe"
}
```

Then run:

```sh
go run ./cmd/blender-box windows check --target target.json --json
```

The command streams one bounded, read-only PowerShell inspection over SSH and returns versioned UTF-8 JSON. It verifies the console-user SID, declared executable and work-root access, trusted path authorities through the volume root, and the complete root Scheduled Task action, principal, settings, and security descriptor. Access inspection treats every applicable-rights deny ACE conservatively because an SSH check does not own the interactive task token; operator-managed setup paths should not use deny ACEs. A failed requirement returns `status: "fail"`; malformed or oversized transport output is an error.

## Proposed boundary

- `blender-box` owns SSH, Windows setup checks, Host Locks, payload transfer, Scenarios, evidence, validation, and cleanup.
- `blendersessiond` runs on Windows and owns Blender discovery, launch, health, MCP calls, and exact process-tree stop.
- Consuming repos own Blender scripts, add-ons, scenes, expected outputs, and domain assertions.

## Research

Read the [Blender Box research brief](docs/research/blender-box-research.html).

## Development

Run the same gate used by GitHub Actions:

```sh
./scripts/ci all
```

The current gate checks the repository, Go CLI, and CI contract on Linux, macOS, and Windows. Live Windows Blender proof stays opt-in and separate from pull-request CI.
