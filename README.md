# blender-box

Remote Blender GUI Scenario runner for owned Windows hosts.

Blender Box runs from a developer checkout, reaches Windows over SSH, stages a declared Run Payload, starts Blender in the logged-in desktop through an interactive Scheduled Task, drives the host-local `blendersessiond`, and returns structured and visual evidence.

Tailscale currently provides private host reachability through the configured SSH alias. Blender's MCP add-on remains bound to Windows loopback.

## Status

Slice 0 provides read-only inspection, explicit setup, a fenced remote Scenario run, reconnect status, exact stop, and a local Evidence Bundle. The default test suite uses fake SSH, Scheduled Task, daemon, filesystem, and Blender boundaries. Real Windows Blender proof is opt-in.

## Windows target

Create a non-secret target file with absolute Windows paths and a safe SSH config alias:

```json
{
  "schema_version": 1,
  "ssh_alias": "owned-windows-host",
  "ssh_user": "HOST\\controller",
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

The command streams one bounded, read-only PowerShell inspection over SSH and returns versioned UTF-8 JSON. It verifies the SSH and console-user SIDs, UAC limited-token policy, declared executable and work-root access, trusted path authorities through the volume root, and the complete root Scheduled Task action, principal, settings, and security descriptor. The task DACL must grant the declared SSH user direct launch authority; the SSH and interactive users may be the same account. Access inspection treats every applicable-rights deny ACE conservatively because an SSH check does not own the interactive task token; operator-managed setup paths should not use deny ACEs. A failed requirement returns `status: "fail"`; malformed or oversized transport output is an error.

`session_broker_executable` and `host_executable` must be inside `work_root`. Blender may use an operator-managed installation elsewhere.

## Explicit setup

Build the Windows host binary, inspect the plan, then add `--apply` only for the verified owned host:

```sh
GOOS=windows GOARCH=amd64 go build -o /tmp/blender-box.exe ./cmd/blender-box
go run ./cmd/blender-box windows setup --target target.json --host-binary /tmp/blender-box.exe --json
go run ./cmd/blender-box windows setup --target target.json --host-binary /tmp/blender-box.exe --apply --json
go run ./cmd/blender-box windows check --target target.json --json
```

Plan mode makes no SSH call. Apply rejects an empty binary, validates every existing physical path component, and guards each mutation phase with the same OS-released operation lock used by Runs. While holding it, setup refuses an active Host Lock, secures the declared work root and existing managed state without following reparse points, rehashes and atomically publishes the binary, applies the declared ACLs, and registers the exact no-trigger interactive task with limited rights, `IgnoreNew`, and no execution time limit. The bounded binary and hash-verified setup program travel over SCP; only the small bounded setup guard uses stdin. Setup requires the declared Blender and compatible `blendersessiond` executables to exist. A standard task-local Python virtual environment is compatible; its launcher must resolve without ambient `PYTHONPATH`. Setup does not install Blender, launch it, change SSH, Tailscale, or firewall settings, or expose Blender's loopback MCP port.

## Run a Scenario

A slice 0 payload declares regular files, one Python Scenario entry point, a bounded daemon read timeout, and viewport evidence policy:

```json
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
```

Run and recover through the public commands:

```sh
go run ./cmd/blender-box run --target target.json --payload payload.json --timeout 20m --json
go run ./cmd/blender-box status --target target.json --run bbx_... --json
go run ./cmd/blender-box stop --target target.json --run bbx_... --json
```

`run` writes `RUN_ID=bbx_...` to stderr before validation or remote work; JSON mode writes one versioned success or failure result to stdout. The client acquires the host-owned lock, transfers and rehashes bounded payload files, triggers the static task, pins the exact returned `blendersessiond` Session identity, then waits up to two minutes for `status` to report that same Session's process and loopback socket healthy before the Scenario call. While no identity exists, the client may replay only the same fenced start request so an `IgnoreNew` trigger cannot strand the Run. The Run deadline remains authoritative. `stop` recovers the full request and Session fence from host state. It never stops Blender by name, port, path, or guessed PID.

The default bundle is `artifacts/blender-box/<run-id>/`. `manifest.json` records non-empty evidence paths, types, sizes, SHA-256 hashes, and viewport capture provenance. `evidence.json` records Run, request, deadline, exact Session identity, terminal state, and cleanup. Scenario and viewport files are fetched only from the declared manifest and published without replacement. Viewport PNG dimensions are checked independently against the declared capture dimensions on both sides of SSH.

## Boundary

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
