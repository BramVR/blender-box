# Blender Box

![Blender Box sends a Run Payload to a remote Blender host and returns viewport evidence](docs/assets/blender-box-banner.png)

Run declared Blender Scenarios on an owned desktop from a developer checkout. Windows uses an interactive Scheduled Task. The Linux adapter targets a fixed Ubuntu GNOME Xorg configuration.

Blender Box sends a bounded Run Payload over SSH and starts the host entry point through the platform desktop launcher. A host-local [`blendersessiond`](https://github.com/BramVR/blendersessiond) owns the Blender process. The client returns a verified Evidence Bundle, then cleans up the exact Session that it started.

Tailscale can provide private reachability. Blender Box connects through an operator SSH alias or a paired target with a pinned endpoint and key. Blender's MCP add-on stays bound to host loopback.

## Project status

The first end-to-end slice supports read-only host checks, explicit setup, local planning, capture-aware host diagnosis, remote Scenario runs, reconnect status, exact stop, and local Evidence Bundles. Windows Scenarios can request distinct viewport, Blender-window, and opt-in Windows-desktop captures. Linux supports viewport capture.

The default test suite replaces SSH, the Scheduled Task, `blendersessiond`, the filesystem, and Blender with fakes. Proof against a real Blender host is opt-in. The [Linux host path](docs/linux.md) requires an externally provisioned reviewed daemon runtime; the current wheel is rejected. Native Linux, Blender, and hosted acceptance remain outstanding.

The repository supplies [Windows onboarding proof](docs/windows-onboarding-proof.md) for baseline Runs, named targets, and host installation. Each live variant needs separate, exact authorization. Hosted execution remains blocked until private Run recovery authority can survive loss of its controller. A local pass does not replace a required hosted job.

## Drive a Blender UI workflow

Payload schema 3 requires one `ui_actions` batch after the preparation script declaration. Use schema 1 or 2 for Scenarios without UI actions:

```json
{
  "schema_version": 3,
  "files": [{"source": "prepare.py", "destination": "prepare.py"}],
  "scenario": {
    "script": "prepare.py",
    "capture_blender_window": true,
    "ui_actions": {
      "schema_version": 1,
      "timeout_seconds": 15,
      "actions": [
        {"type": "click", "x": 400, "y": 300, "button": "left"},
        {"type": "key", "key": "F2"},
        {"type": "text", "text": "Blender Box proof"},
        {"type": "key", "key": "ENTER"}
      ]
    }
  }
}
```

Choose coordinates for your Blender layout. Coordinates are physical client pixels from the top-left, bounded by the verified window. The preparation script runs first and must return the ordinary passing Scenario Result. The batch then runs in the foreground Blender window owned by that exact Session.

UI action batches require a Windows target. Linux targets refuse them before host contact.

Run `plan` to inspect the redacted batch and capture paths. Its `expected_evidence` field lists each evidence type once; `captures` lists individual files, including both Blender-window images. Run `doctor` before launching. UI actions require an updated host and a daemon advertising `blender-ui-events-v1`, plus Blender support for `--enable-event-simulate`. The host opts that Session into event simulation with `--enable-ui-events`. Blender's `--enable-event-simulate` mode disables real physical mouse and keyboard input in that Session.

The action vocabulary and limits are:

- `click` requires `x`, `y`, and `button`, one of `left`, `middle`, or `right`. Coordinates must be within 0..32767 and inside the client area.
- `key` accepts `A` through `Z`, `0` through `9`, `F1` through `F12`, `ENTER`, `ESC`, `TAB`, `SPACE`, `BACKSPACE`, `DELETE`, `LEFT`, `RIGHT`, `UP`, `DOWN`, `HOME`, `END`, `PAGEUP`, and `PAGEDOWN`. Optional `modifiers` contains distinct `ctrl`, `shift`, or `alt` values. Each action presses and releases its own keys.
- `text` accepts 1..256 Unicode scalars without control or format characters. Use key actions for Enter and Tab. IME composition, clipboard paste, and OS dialogs are outside this contract.
- A batch contains 1..64 actions, at most 1024 text scalars, and a 1..30 second timeout. Each action also has a five-second deadline.

Start a batch with a click to select the editor for later keys and text. A batch starting with a key or text action requires the physical cursor to already be inside the Blender client.

The backend targets Blender's own window event queue. It does not send global Windows input or move the physical cursor. Focus loss, multiple Blender windows, replacement windows, and coordinate mismatches stop the batch.

`queued` receipts mean the event-processing barrier passed. Verify the intended UI change from the images or your Scenario's own checks. With Blender-window capture enabled, the bundle contains before and after images plus `result/ui-actions.json`. On failure, it retains available evidence and stops the exact Session. An uncertain action is never replayed automatically. Receipts omit entered text, but your payload and screenshots can contain it.

The [UI action contract](docs/architecture/0005-session-local-ui-actions.md) describes identity, acknowledgement, and recovery.

## Requirements

For Windows, you need:

- Go 1.23 or later on the developer machine.
- An owned Windows host with OpenSSH and an interactive user who is logged in.
- A safe alias for that host in your SSH config.
- An existing Blender installation and a supported standard 64-bit CPython 3.11 through 3.14 installation on Windows.
- A verified Windows bootstrap executable and a pinned runtime bundle for [host installation](docs/windows-installation.md), or an already prepared compatible host.
- One Windows identity for both SSH control and the interactive Scheduled Task. The account names may differ, but they must resolve to the same SID.

Setup provisions its own isolated `blendersessiond` runtime from declared, hashed files. It does not install Blender or Python, or change SSH, Tailscale, or firewall settings.

## Create a target profile

Keep operator configuration outside the consuming repository. The [installer](docs/windows-installation.md) can export a complete target file. For an existing prepared host, its shape is:

```json
{
  "schema_version": 2,
  "platform": "windows",
  "ssh_alias": "owned-windows-host",
  "windows": {
    "ssh_user": "HOST\\operator",
    "work_root": "C:\\BlenderBox",
    "interactive_user": "HOST\\operator",
    "task_name": "BlenderBoxHost",
    "blender_executable": "C:\\Program Files\\Blender Foundation\\Blender\\blender.exe",
    "session_broker_executable": "C:\\BlenderBox\\bin\\blendersessiond.exe",
    "host_executable": "C:\\BlenderBox\\bin\\blender-box.exe"
  }
}
```

Keep credentials, hostnames, IP addresses, and private network details out of this file. `ssh_alias` selects an entry from your SSH config.

Both `session_broker_executable` and `host_executable` must be inside `work_root` and below a dedicated executable directory. Blender may be installed elsewhere. The work root must be an ASCII drive path without spaces for the Run transport's legacy SCP support.

Version 2 also accepts a strict `linux` body for Ubuntu 24.04 GNOME on Xorg. Follow the [Linux host guide](docs/linux.md) for its UID, desktop, static unit, and reviewed runtime requirements. Existing flat schema version 1 Windows files remain valid input with unchanged normalized bytes and fingerprints. Unsupported platforms and malformed documents fail before a connection or setup change.

## Save a named target

Import the file once, using its path outside the repository:

```sh
go run ./cmd/blender-box targets import studio --file /path/to/target.json --json
go run ./cmd/blender-box targets list --json
go run ./cmd/blender-box targets show studio --json
```

Import stores a copy. Changing or deleting the source file does not change the saved target. `show` displays alias targets as schema version 2, including profiles imported from version 1. Paired targets retain schema version 3 and their complete connection identity.

Names start with a lowercase ASCII letter and contain at most 63 lowercase letters, digits, underscores, or hyphens. Reserved Windows device names are rejected. A collision fails unless you pass `--replace`.

Import, list, show, and forget work offline. Forget removes only the saved local profile. It does not revoke SSH access, stop a Session, or delete Run recovery records.

Every target-taking command accepts either `--target-name NAME` or `--target PATH`. Supply exactly one. There is no default target or automatic fallback. The examples below use `studio`; explicit file selection remains available.

Saved profiles and Run recovery records use the operating system's user configuration directory under `blender-box`. Set `BLENDER_BOX_CONFIG_DIR` to an absolute, operator-owned directory to isolate another configuration. Preserve that directory for later recovery, even when using a custom Evidence Bundle directory.

## Prepare local pairing

The local pairing client accepts independently trusted host offers and enrollment receipts. Native offer creation, enrollment, revocation and SSH preparation are not implemented yet. This slice does not provide a complete onboarding flow or prove host readiness.

On a POSIX client with `ssh-keygen`, an authorized test or integration can use these entrypoints with its trusted input files and independently verified digests:

```sh
blender-box pair prepare studio --offer /path/to/offer.json --trust-offer "$OFFER_DIGEST" --json
blender-box pair status studio --json
blender-box pair complete studio --receipt /path/to/receipt.json --trust-receipt "$RECEIPT_DIGEST" --json
```

Do not compute a digest from an untrusted file and treat that as host approval. Preparation outputs a public intent and retains its private key locally. Repeating the same operation preserves recovery state. Completion verifies the original intent and saves a schema-3 target without replacing another profile. Readiness stays unchecked until `doctor` succeeds.

Paired transport pins the host's Ed25519 key and the dedicated client key for both SSH and SCP. It refuses missing or changed credentials. Windows clients refuse paired credentials until native owner and ACL checks are available. Existing alias profiles remain supported.

Keep pairing state private and retain it after an interrupted request. Local cancellation does not revoke a grant. See the [client pairing contract](docs/architecture/0008-client-pairing.md) for trust, recovery and unfinished host work.

## Set up the Windows host

Use the [Windows installation guide](docs/windows-installation.md) to build a pinned runtime bundle, inspect the host, review a plan, and explicitly install. Setup runs on Windows through a verified bootstrap executable and exports the target for your developer machine.

```powershell
.\blender-box.exe setup inspect --platform windows --state-root C:\BlenderBox --json
```

Installation and removal require `--apply`. Repeats use the recorded installation identity. Removal preserves shared Run authority, installation receipts, modified files, and unknown descendants. It refuses active or ambiguous Run state and never stops Blender implicitly.

After a lost setup response, use `setup status` with the recorded installation and operation IDs. `setup stop --apply` requests cancellation of the exact execution token. Unknown execution cleanup or an unsettled task change keeps new Runs and unrelated setup blocked. See [recovery commands](docs/windows-installation.md#repeat-and-recover).

The legacy `windows setup --target-name studio --host-binary EXE --json` command still produces an offline binary preview. Its `--apply` form fails with `legacy-setup-unowned` before SSH. Legacy files and tasks have no installation receipt and cannot be adopted or replaced by name.

## Check the installed host

Run the read-only host check after setup or when the host configuration changes:

```sh
go run ./cmd/blender-box windows check --target-name studio --json
```

The check verifies the Windows identities, managed paths, ACLs, executables, operation locks, setup journals, Scheduled Task, and `blendersessiond` capabilities. Pending setup fails readiness until execution cleanup is known. Existing legacy setup-owner state still receives a trusted-state scan. A failed requirement returns `status: "fail"` without launching Blender.

## Create a Run Payload

A Run Payload lists the files to stage, the Python Scenario entry point, the daemon read timeout, and its capture policy. Each `source` path is relative to the payload document. Each `destination` path is relative to the remote payload root.

Create `payload.json` next to `scenario.py`:

```json
{
  "schema_version": 2,
  "files": [
    {
      "source": "scenario.py",
      "destination": "scenario.py"
    }
  ],
  "scenario": {
    "script": "scenario.py",
    "read_timeout_seconds": 600,
    "capture_viewport": true,
    "capture_blender_window": true,
    "capture_desktop": false
  }
}
```

The Scenario call must return one JSON document with `schema_version: 1` and `status: "pass"`. Payload schema 1 remains valid for the existing viewport-only contract. Blender-window and desktop captures require payload schema 2 and a Windows target. Linux `plan`, `doctor`, and `run` refuse those captures before acquiring a Host Lock.

- `capture_viewport` records scene pixels through the daemon's offscreen or window-grab path.
- `capture_blender_window` records the full Blender window, including its UI chrome, through `bpy.ops.screen.screenshot` on the exact Session.
- `capture_desktop` records the Windows virtual desktop. It is always off by default and can contain unrelated private information.

A successful Run requires exactly one file for each requested capture. Missing, duplicate, malformed, or unsolicited evidence fails the Run.

Validate locally without contacting the host, then inspect the installed host capabilities:

```sh
go run ./cmd/blender-box plan --target-name studio --payload payload.json --json
go run ./cmd/blender-box doctor --target-name studio --payload payload.json --json
```

`doctor` is read-only. It checks the target and payload, runs the installed host inspection, and reports support for every requested capture before staging or launching Blender. Schema 1 viewport-only Payloads retain the existing host inspection path. Every schema 2 Payload requires the matching upgraded host binary.

## Run the Scenario

Start the Run from the developer checkout:

```sh
go run ./cmd/blender-box run \
	--target-name studio \
	--payload payload.json \
	--timeout 20m \
	--json
```

`run` writes `RUN_ID=bbx_...` to stderr before validation or remote work. With `--json`, stdout contains one versioned success or failure result.

The client acquires the Host Lock, stages and verifies the Run Payload, starts the fixed desktop launcher, and records the exact `blendersessiond` Session identity. It fetches and verifies evidence before it stops that Session and removes the remote Run files.

## Recover or stop a Run

If the client disconnects, use the Run ID to read the durable host receipt:

```sh
go run ./cmd/blender-box status \
	--target-name studio \
	--run bbx_... \
	--json
```

Stop an active Run with the same Run ID:

```sh
go run ./cmd/blender-box stop \
	--target-name studio \
	--run bbx_... \
	--json
```

Before contacting the host, recovery compares the selected target with the original Run's local authority record. Replacing `studio` with different configuration cannot redirect `status`, `stop`, or cleanup. A missing profile or missing recovery record fails locally.

To recover after renaming or forgetting a target, supply an original profile file with `--target`, or import identical configuration under a new name. Equivalent version 1 and version 2 profiles match. Changing an alias, identity, work root, task, or executable path does not match. Keep the original configuration while a Run may still need cleanup.

The local record preserves the original complete request claim and the first accepted Session identity. `stop` compares host receipts with that authority and stops only the exact Session. It never stops Blender by process name, port, executable path, or a guessed PID. Runs created before local recovery records existed require the original client and original target; this client cannot reconstruct missing authority from a selected host's reply.

This check pins declared target configuration. Alias targets still use operator-managed SSH configuration. Paired targets also bind their direct endpoint, host public key and dedicated client-key fingerprint. Missing pairing credentials never fall back to an alias or another key. See the [target contract](docs/architecture/target-contract.md) for the boundary and storage rules.

After cleanup, replace or forget a saved profile when needed:

```sh
go run ./cmd/blender-box targets import studio --file /path/to/replacement.json --replace --json
go run ./cmd/blender-box targets forget studio --json
```

## Evidence Bundle

By default, each Run reserves `artifacts/blender-box/<run-id>/` before it contacts the host. Pass `--evidence-dir` to choose another new directory.

A successful Evidence Bundle contains:

- `manifest.json` with evidence paths, types, sizes, SHA-256 hashes, and capture provenance.
- `evidence.json` with the Run identity, request identity, deadline, Session identity, terminal state, and cleanup result.
- `result/scenario-result.json` with the Scenario Result.
- `screenshots/viewport.png` when the Run requests a viewport capture.
- `screenshots/blender-window.png` when the Run requests a Blender-window capture.
- `screenshots/desktop.png` only when the Run explicitly requests a desktop capture.

Schema 2 manifest entries record the capture type, method, dimensions, media type, byte size, SHA-256, source path, and exact Session identity. The client verifies hashes and PNG dimensions after transfer and never replaces an existing evidence file. Keep desktop Evidence Bundles private unless you have reviewed the image.

## Ownership boundaries

- `blender-box` owns SSH, host checks, setup, Host Locks, payload transfer, Scenario orchestration, evidence verification, and cleanup.
- `blendersessiond` owns Blender discovery, launch, health checks, MCP calls, and exact process-tree stop on the host.
- Consuming repositories own Blender scripts, add-ons, scenes, expected outputs, and domain assertions.

SSH is the control and file-transfer channel. Blender Box never exposes or forwards Blender's loopback MCP port.

## Development

Run the same repository gate that GitHub Actions uses:

```sh
./scripts/ci all
```

The gate runs on Linux, macOS, and Windows without contacting a Blender host. See [CI architecture](docs/architecture/ci.md) for the hosted and live-proof boundary.

## Design documents

- [Run boundary](docs/architecture/0001-slice-0-run-boundary.md) defines orchestration, recovery, evidence, and cleanup.
- [Target contract](docs/architecture/target-contract.md) defines named profiles, platform versions, and original-target recovery.
- [Windows installation](docs/windows-installation.md) covers runtime bundles, preview, installation, retries, and owned removal.
- [Installation ownership](docs/architecture/0007-windows-installation-ownership.md) defines runtime receipts and maintenance fencing.
- [Windows identity boundary](docs/architecture/0002-slice-0-windows-identity.md) explains why the current slice uses one Windows SID.
- [`blendersessiond` capability gate](docs/architecture/0003-session-broker-capability-gate.md) defines the daemon contract required before launch.
- [Linux host boundary](docs/architecture/0006-linux-host.md) defines desktop service lifetime, reviewed daemon imports, setup, and acceptance gaps.
- [Research brief](docs/research/blender-box-research.html) records the broader product research and proposed contracts.
