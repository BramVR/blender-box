---
summary: Run authorized Linux Blender proof and retain exact recovery authority and evidence.
read_when:
  - Running or extending Linux Blender proof.
  - Reviewing Linux proof prerequisites or the hosted retention refusal.
---

# Run Linux Blender proof

Use this guide to verify a clean candidate through the public Linux CLI. The proof creates the existing baseline cube, validates its viewport Evidence Bundle, reconnects through fresh CLI processes, and checks exact stop and cleanup.

Hosted execution currently fails with `hosted-recovery-retention-unavailable`. A workflow definition or passing fake tests do not establish native Linux or hosted acceptance.

## Prepare an authorized desktop

Use an owned Ubuntu 24.04 LTS amd64 desktop with GNOME on Xorg, systemd 255, and one active local graphical login. The SSH account and desktop must have the same UID. This is the intended support configuration, not an observation of any particular host. Wayland, Xvfb, remote graphical sessions, ambiguous logins, and other architectures are outside this proof.

Provision Blender 5.2.0 and the reviewed daemon runtime separately. The daemon uses a dedicated copied CPython 3.12 environment and the complete reviewed package manifest. Its provenance ID is `blendersessiond-6d40e403-posix-9a54bfb9`. The installed package must actually match that manifest. Declaring this ID or passing the old capability probe cannot make an uncorrected wheel compatible.

The daemon correction has shared POSIX fake-process evidence. It does not yet have native Linux or real Blender proof. Keep the original wheel, source revision, patch digests, and package verification receipts privately. This proof and product setup never install or modify Python, the daemon, Blender, or the desktop.

Prepare existing SSH trust and an operator-owned fixture before running the proof. Keep the host's shared Host Lock root. A different root is not permission to bypass another Run or unrelated Blender work. See the [Linux target and setup guide](linux.md) for the product contract.

## Write the private operator document

Store a schema version 1 operator document outside the repository, with mode `0600`. It contains these fields:

- `target`. The exact Linux schema version 2 target. Include `home`, the declared UID, the managed work root, executable paths, unit name, desktop values, and daemon runtime.
- `expected_host`. Exactly `hostname`, `distribution`, `uid`, `blender_version`, and `daemon_provenance_id`. Require `ubuntu-24.04-gnome-xorg`, `5.2.0`, and the provenance ID above. The expected UID must equal the target UID.
- `fixture`. Its exact `id`, `kind` of `shared-existing` or `dedicated`, and `state` of `prepared`. These declarations do not create ownership or authorize reset.
- `authorization`. The exact full `candidate_sha`, matching `fixture_id`, `launch: true`, and `setup: null` unless setup was separately approved.
- `ssh_config`. Optional absolute path to an existing private SSH configuration. The proof snapshots it privately and enforces strict host-key verification, batch mode, and no forwarding. Without this field, the existing operator-managed SSH configuration applies.
- `publish_viewport`. Optional boolean, default `false`. Set it only when publication of the baseline viewport is authorized.

For an approved setup, replace `setup: null` with an object containing `candidate_sha`, `target_sha256`, `prior_host_sha256`, and `scope: "linux-setup-binary-unit-state"`. The target hash is SHA-256 of the supplied target JSON serialized with sorted keys and compact separators. It is separate from the product's normalized recovery fingerprint. Use a prior host hash of `null` only when the expected destination is absent.

Review the exact setup plan before granting that authorization. Setup can publish the candidate host binary, private Blender Box state, and the declared static user service. Its plan names the exact destinations and contains the unit bytes and their hash. It grants no runtime installation, desktop changes, fixture reset, or service stop. The proof compares the applied unit and destinations with the preceding plan and rechecks the installed binary hash.

## Run the candidate locally

Use a macOS or Linux controller with Python 3.12 and the repository's Go version. Keep the candidate checkout clean and provide its full 40-character commit SHA. Choose a fresh output directory with an existing parent, outside the checkout or under its ignored `.blender-box/` directory.

```sh
python3 scripts/linux_blender_proof.py baseline \
	--candidate "$CANDIDATE_SHA" \
	--candidate-checkout "$CANDIDATE_CHECKOUT" \
	--operator-config "$BLENDER_BOX_PROOF_CONFIG" \
	--output "$PROOF_OUTPUT" \
	--execution local
```

The runner validates the operator document and clean candidate before host contact. Its read-only SSH probe uses system Python with isolated startup and site initialization disabled. It checks expected hostname, UID, home, Ubuntu version, amd64 architecture, existing host hash, Blender process count, and Host Lock absence. Process enumeration is an activity check and never authorizes cleanup.

The runner builds the client and Linux amd64 host binary. It calls `linux setup` without `--apply` to verify the plan. If the installed host hash differs or the file is absent, it requires exact setup authorization before invoking `--apply`. A matching binary does not trigger setup merely to repair an unprepared fixture. Readiness must still pass.

`linux check` must verify all six required checks: `host.linux`, `host.desktop`, `daemon.runtime`, `host.unit`, `work-root.access`, and `blender.executable`. The proof also requires its observed Blender version to equal `5.2.0`. Only then does it invoke `run`, validate the cube and viewport, and perform `status`, `stop`, and final `status` through fresh public CLI processes.

Read `public/outcome.json`. Require overall `pass` and all six outcomes: `preparation`, `readiness`, `scenario`, `evidence`, `recovery`, and `cleanup`. Inspect the exact Run ID, request identity and hash, Session identity, candidate and binary hashes, viewport provenance and dimensions, matching remote and local artifact hashes, and all four cleanup facts. The complete deadline and evidence records remain in the private command receipts and retained product bundle under `artifacts/blender-box/<run-id>/`.

A fresh `status` proves reconnect. The final `stop` proves idempotent exact settlement after the default Run cleanup. This proof does not deliberately drop SSH, crash the service, log out the desktop, resume a Scenario, reset a fixture, or prove a kept Session. Those outcomes cannot be inferred from its success.

## Retain authority when cleanup is unknown

The proof stores `BLENDER_BOX_CONFIG_DIR` under its private output. The product writes the complete original Run claim and normalized target fingerprint there before its first Run contact, then separately pins the first accepted Session identity. Preserve this directory, the original target, private command receipts, and Run journal until cleanup is known.

The public Run ID appears as soon as the CLI emits it. Failure triggers bounded public `status`, `stop`, and `status` recovery when local subprocess ownership remains known. A recovered cleanup result does not convert a failed Scenario into a passing proof. Unknown cleanup keeps the report failed and the authority files intact.

Use the original configuration and private authority for recovery. Replacing a target, copying only a Run ID, or deleting the local configuration cannot recreate authority. Never reset host state or stop Blender by process name to make a failed proof pass.

## Inspect the hosted refusal

The required workflow is `Linux Blender proof`, job `linux-blender-proof`. It accepts a full candidate SHA through an authorized main-branch dispatch and uses an independently pinned trusted driver. Reruns and untrusted dispatches fail before proof execution.

The workflow checks out only the trusted driver, then invokes the same runner with `--execution hosted`. The runner unconditionally refuses hosted work until private original authority can survive controller loss. This occurs before operator loading, candidate commands, host inspection, credentials, or network enrollment. The current workflow contains no candidate checkout, host secrets, Tailscale action, or local-execution bypass.

Read the failed job and its public outcome. It must report `hosted-recovery-retention-unavailable`, no Run, and no cleanup claim. Only `public/outcome.json` uploads. Private configuration, logs, journals, and arbitrary artifact globs never upload. Local viewport publication remains separately opt-in.

Before hosted execution can be enabled, implement and verify approved private durable authority retention and its recovery procedure. Then review protected host authorization, prepared fixture ownership, scoped credentials, immutable candidate execution, and network access as separate work. Adding this workflow does not enroll those prerequisites. A skipped, blocked, cancelled, fake-only, or local run leaves required hosted proof incomplete.

## Check the proof code without a host

Run the shared regression tests and workflow validation:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/ci -p 'test_*proof.py' -v
actionlint .github/workflows/linux-blender-proof.yml
./scripts/ci all
```

The tests exercise the real proof runner with fake external commands, real bounded bundle parsing, Linux setup and readiness failures, exact recovery, private output, and the actual CLI's hosted refusal. Existing Windows proof tests remain required. These checks do not launch Blender or establish native systemd lifetime behavior.
