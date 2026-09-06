---
summary: Prepare and run the supported Linux desktop configuration through SSH.
read_when:
  - Configuring a Linux target or diagnosing Linux setup and readiness refusal.
  - Provisioning the reviewed daemon runtime for Linux proof.
---

# Run a Scenario on a Linux desktop

This guide is for the operator of an owned Linux Blender host. Setup writes the declared Blender Box binary, private state, and static user unit. It does not install Python, Blender, the daemon, or a desktop.

The implemented Linux path has local tests with fake external boundaries. Native Linux, systemd, Blender, and hosted acceptance remain outstanding. The currently available daemon wheel lacks the reviewed POSIX correction and is rejected. Obtain the corrected runtime from its provider before attempting a real Run.

## Prepare the host prerequisites

Use Ubuntu 24.04 LTS, GNOME on Xorg, systemd 255 with unified cgroup v2, CPython 3.12, and Blender 5.2.0. Log in locally with the same UID used by SSH. Keep exactly one graphical session for that UID. Wayland, remote graphical sessions, Xvfb, other desktops, and multiple graphical sessions fail readiness.

Provide a safe SSH alias through your existing SSH configuration. Keep Blender's MCP port on host loopback. No port forwarding or desktop service installation is part of setup.

Have the runtime provider supply a dedicated copied CPython venv that matches the [reviewed runtime layout](architecture/0006-linux-host.md#reviewed-runtime-layout). A stock venv is insufficient. The verified package contains the reviewed POSIX launch correction, and the whole import tree must satisfy the allowlist. No product command upgrades or repairs this runtime.

## Create the private target

Keep the target file outside the consuming repository. Replace the example values with the owned host's configuration.

```json
{
  "schema_version": 2,
  "platform": "linux",
  "ssh_alias": "owned-linux-host",
  "linux": {
    "distribution": "ubuntu-24.04-gnome-xorg",
    "uid": 1000,
    "home": "/home/operator",
    "work_root": "/home/operator/blender-box",
    "host_executable": "/home/operator/blender-box/bin/blender-box",
    "blender_executable": "/opt/blender-5.2.0/blender",
    "unit_name": "blender-box.service",
    "desktop": {
      "display": ":0",
      "xauthority": "/run/user/1000/gdm/Xauthority"
    },
    "daemon": {
      "venv_root": "/home/operator/blender-box-daemon",
      "python_executable": "/home/operator/blender-box-daemon/bin/python3",
      "provenance_id": "blendersessiond-6d40e403-posix-9a54bfb9"
    }
  }
}
```

Use absolute ASCII paths without spaces, shell syntax, symlinks, or `.` and `..` segments. The host executable belongs directly inside `work_root/bin`. Keep the daemon venv and Xauthority outside the managed work root. The configured home must equal the UID's passwd home. An alternate `XDG_CONFIG_HOME` is rejected.

Import the target into private local storage:

```sh
blender-box targets import linux-studio --file /path/to/linux-target.json --json
```

Preserve that configuration and the local Run authority records for recovery. The same [target selection and recovery rules](architecture/target-contract.md) apply to Windows and Linux.

## Preview and apply setup

Build a host binary for the host architecture. For an x86-64 host:

```sh
GOOS=linux GOARCH=amd64 go build -o /tmp/blender-box-linux ./cmd/blender-box
```

Preview the exact binary hash, byte count, unit contents, unit hash, destinations, and unverified prerequisites:

```sh
blender-box linux setup --target-name linux-studio --host-binary /tmp/blender-box-linux --json
```

Preview performs no SSH call and no remote write. Its prerequisite list records what remains unverified. It does not claim the host is ready.

After verifying the owned target, apply the bounded setup:

```sh
blender-box linux setup --target-name linux-studio --host-binary /tmp/blender-box-linux --apply --json
```

Apply refuses a Host Lock, an active or transitioning unit, foreign unit configuration, unsafe paths, and unrecognized existing artifacts. It publishes the host binary before reloading the user manager, verifies the effective static unit, and returns matching publication hashes. It neither enables the unit nor requires linger.

A scoped `.linux-setup.json` receipt recognizes later replacement and interrupted publication. Retry can reconcile complete owned temporary files and recorded pending hashes. A completed final ownership temporary is published only when its identity and installed hashes exactly match the prior pending receipt and both installed artifacts. This reconciliation precedes applying the same or a different candidate. A pending ownership temporary for a different candidate still requires inspection or a retry with its matching candidate. Partial or mismatched temporary files remain for operator inspection. Setup does not delete uncertain artifacts. Changing the managed root or unit destination is a separate operator migration.

## Check readiness and run

Run the read-only check:

```sh
blender-box linux check --target-name linux-studio --json
```

A passing check reports Blender `5.2.0` and six required checks. Failures identify the platform, desktop, runtime, unit, state access, or Blender prerequisite. The check queries Blender's version and the daemon's existing capabilities without starting a Blender Session.

Prepare a [Run Payload](../README.md#create-a-run-payload), then use the shared commands:

```sh
blender-box plan --target-name linux-studio --payload payload.json --json
blender-box doctor --target-name linux-studio --payload payload.json --json
blender-box run --target-name linux-studio --payload payload.json --json
blender-box status --target-name linux-studio --run bbx_... --json
blender-box stop --target-name linux-studio --run bbx_... --json
```

Linux supports viewport capture with payload schema 1 or 2. Blender-window capture, desktop capture, and UI action batches are unsupported. `plan`, `doctor`, and `run` refuse those requests before acquiring a Host Lock. Direct host requests refuse them before publication or daemon launch.

The static user service owns the host entry point's lifetime. The daemon owns Blender and its exact Session identity. The returned viewport capture includes its method, dimensions, and verified hashes. An `offscreen` image does not prove Blender window chrome or desktop dialogs.

Each Linux Run stages a private `tmp` directory and passes it as `TMPDIR` to the daemon and Blender descendants. Launch refuses a missing or unsafe temporary directory. Exact settlement removes its temporary files with the owned Run root; recovery and stop remain available if the directory is missing. Operator temporary-directory variables are not inherited.

## Recover after interruption

Use `status` and exact `stop` after SSH loss or desktop logout. These commands do not require a currently active desktop. Preserve the original target and private controller authority. A changed target or replacement Session is never adopted.

After a host-process crash, use exact settlement before starting another Run. Blender Box does not resume the interrupted Scenario. A remaining descendant can keep the unit active until exact cleanup finishes. A fresh Run refuses before publishing its pending request while the prior service remains active. Retry after that service becomes inactive.

A failed unit requires operator attention even after the Run reports exact cleanup. Inspect the exact setup-owned unit and its remaining processes before clearing its failed state. Blender Box does not automatically reset, stop, restart, or kill a unit. Unit disappearance and desktop logout never establish successful Session cleanup.

For opt-in proof and the remaining hosted retention prerequisite, use [Linux Blender proof](linux-proof.md).
