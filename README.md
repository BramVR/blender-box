# blender-box

Remote Blender GUI Scenario runner for owned Windows hosts.

Blender Box runs from a developer checkout, reaches Windows over SSH, stages a declared Run Payload, starts Blender in the logged-in desktop through an interactive Scheduled Task, drives the host-local `blendersessiond`, and returns structured and visual evidence.

Tailscale currently provides private host reachability through the configured SSH alias. Blender's MCP add-on remains bound to Windows loopback.

## Status

Research and product design. No CLI implementation yet.

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

The current gate checks the repository and CI contract on Linux, macOS, and Windows. It will pick up Go and Python checks when their project files land. Live Windows Blender proof stays opt-in and separate from pull-request CI.
