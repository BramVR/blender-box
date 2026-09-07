---
summary: Run Windows baseline, named-target, and installation proof with private authorization and verified evidence.
read_when:
  - Running or extending Windows onboarding proof.
  - Configuring trusted live CI or preparing onboarding fixtures.
---

# Run Windows onboarding proof

Use this guide to prove a candidate through the existing Windows Run path. The baseline creates a cube in a fresh Blender Session, returns a viewport Evidence Bundle, reconnects, and verifies exact cleanup. It does not install Blender or the daemon, enroll SSH or Tailscale, pair a host, or reset an installation.

## Prepare the private configuration

Select an owned Windows desktop with a logged-in interactive user, a compatible daemon, and an existing target profile. The SSH user and interactive task must resolve to the same SID. Preserve the host's existing shared Host Lock root; creating another root is not a way to bypass activity on the desktop.

Record the expected hostname, Windows build, Blender version, interactive identity SID, daemon executable hash, and exact target in a private operator document outside the repository. Retain the daemon source revision, any patch digest, wheel hash, installed-source verification, and Python version beside it. A package version alone does not prove the required `blender-box-v1` and `typed-call-error-reason` capabilities. The retired daemon setup-owner capability is not a runtime requirement.

Use schema version 1 with these fields:

- `target`. The complete target JSON from the [target profile guide](../README.md#create-a-target-profile). Flat target schema version 1 and nested Windows version 2 are accepted; the operator document itself remains schema version 1.
- `expected_host`. `hostname`, `windows_build` (Windows `BuildNumber`, such as `19045`), `blender_version` (the executable's exact `ProductVersion`), `identity_sid`, and `daemon_sha256`.
- `fixture`. Its exact `id`, `kind` (`shared-existing` or `dedicated`), and `state` (`prepared`). These declarations do not create ownership or authorize reset.
- `authorization`. The exact `candidate_sha`, matching `fixture_id`, `launch: true`, and `setup: null` when setup changes are not permitted.
- `ssh_config`. Optional absolute path to a private SSH configuration. Use strict host-key verification and an existing trusted host key. The runner keeps this configuration separate from your normal SSH files.
- `publish_viewport`. Optional boolean, default `false`. Explicitly permit publication only after reviewing the baseline capture policy.

The legacy `setup` authorization shape binds `candidate_sha`, canonical `target_sha256`, `prior_host_sha256`, and `scope: "windows-setup-binary-task-acls"`. It does not authorize runtime installation or fixture reset. Legacy product apply now refuses with `legacy-setup-unowned` before SSH because its task replacement lacks installation ownership. Baseline and named-target proof therefore require the exact candidate already installed through an owned operator path. A legacy authorization object cannot bypass that refusal.

The setup target hash covers the supplied target document, before version normalization. Keep it distinct from the product's normalized recovery fingerprint. Re-encoding an operator target from version 1 to version 2 requires a new setup authorization hash.

Keep secrets, resolved host details, and raw check output private. Do not copy a previous task's authorization into a new candidate configuration. Readiness and a matching path or task name do not establish ownership.

## Run the candidate locally

Use Python 3.13 or newer on macOS, or Python 3.12 or newer on Linux, with the repository's Go version and a clean candidate checkout. Python added macOS support for [os.waitid](https://docs.python.org/3/library/os.html#os.waitid) in 3.13; the runner uses it to retain exact process-group ownership during cleanup. Windows controllers are unsupported by this proof runner; Windows is the remote Blender host. Set the private configuration's permissions to `0600`. Supply the full commit SHA, private configuration, and a fresh proof-output directory outside the checkout or under its ignored `.blender-box/` directory. The output's parent must exist.

```sh
python3 scripts/onboarding_proof.py baseline \
	--candidate "$CANDIDATE_SHA" \
	--candidate-checkout "$CANDIDATE_CHECKOUT" \
	--operator-config "$BLENDER_BOX_PROOF_CONFIG" \
	--output "$PROOF_OUTPUT" \
	--execution local
```

The runner builds both candidate executables. It verifies the expected host before mutation, rejects unrelated Blender activity or a Host Lock, and requires the installed host binary to match the candidate. A mismatch fails; prepare the exact candidate through the owned installer before retrying. It then runs the public check, Scenario, status, stop, and final status commands.

Read `public/outcome.json` and the private receipts directly. Require a passing overall result and every required baseline outcome. Check the Run ID, request identity/hash/deadline, exact Session identity, binary hashes, matching remote/local artifact hashes, capture provenance, and all four cleanup facts. The retained product bundle lives under `artifacts/blender-box/<run-id>/` in the candidate checkout.

A fresh `status` invocation proves reconnect through another CLI process. The final `stop` proves idempotent exact recovery after the default Run cleanup. It does not prove stopping a kept Session or surviving a deliberately interrupted SSH transport.

The runner persists the validated Run ID in its public failure result as soon as the CLI emits it. If a command then fails, the runner attempts bounded recovery through public `status` and `stop`. Keep the private configuration root, journal, original target, and receipts when cleanup remains unknown. A Run ID alone cannot reconstruct the controller's original authority after a hosted controller is gone. Do not reset the fixture, remove host state, or stop Blender by name to make the proof pass.

## Prove named targets

Run the same candidate with the `named-target` subcommand and a separate fresh output directory:

```sh
python3 scripts/onboarding_proof.py named-target \
	--candidate "$CANDIDATE_SHA" \
	--candidate-checkout "$CANDIDATE_CHECKOUT" \
	--operator-config "$BLENDER_BOX_PROOF_CONFIG" \
	--output "$NAMED_TARGET_PROOF_OUTPUT" \
	--execution local
```

Both variants use an isolated `BLENDER_BOX_CONFIG_DIR` beneath private output. Named-target proof imports a version 1 profile, checks version 2 output through public show/list commands, and uses the saved name for setup, check, the baseline Scenario, and fresh-process recovery. It then replaces the name with valid configuration whose SSH alias differs while the task name stays identical. Both `status` and `stop` must reject the replacement as an original-target mismatch before attempting SSH or SCP; private tripwires verify that boundary.

The runner restores original configuration before exact recovery and cleanup, including after a failed assertion. Require the baseline outcomes plus `target-catalog`, `target-binding`, `target-restoration`, and `target-forget` in `public/outcome.json`. Forgetting proof names removes only saved profiles; retain private Run authority until cleanup is verified. Fake transport tests establish local refusal behavior, but full feature proof still needs the real Scenario and hosted job.

## Prove host installation

Use `host-install` with a separate private operator document and an explicitly authorized dedicated installation fixture. The existing prepared fixture is not disposable. A new installation is a child of the host's existing shared state root; it does not establish another Host Lock namespace.

Prepare and verify the external bootstrap, runtime manifest, and all three artifacts on Windows through the operator's trusted channel. This proof does not upload or provision them. Build host and broker artifacts from the exact candidate, then create the manifest using [the installation guide](windows-installation.md). Keep the bootstrap outside the installation subtree so removal cannot delete the executable performing it.

The installer operator document uses schema version 1 and these fields:

- `platform` is `windows`.
- `connection` contains `ssh_alias` and `windows_user`.
- `expected_host` contains the same five expected-host fields as baseline. Its `daemon_sha256` is the pinned native broker artifact hash.
- `fixture` contains `id`, `kind: "dedicated"`, and `state: "absent"`. `windows-onboarding-prepared-v1` is rejected.
- `installation` contains `id` (`bbxi_` plus 32 lowercase hex characters), `state_root`, `task_name`, `blender`, `python`, and `target_out`. The exported target must be absent and outside the entire state root. It remains after removal for recovery and review.
- `bootstrap` contains its exact Windows `path`, byte `size`, and `sha256`.
- `runtime` contains `local_manifest`, an absolute private controller path, and `remote_manifest` with Windows `path`, byte `size`, and `sha256`. Both copies must have identical bytes. Artifact `name` fields are exact absolute Windows paths already provisioned on the host.
- `before_state` contains `installation_absent: true`, `task_absent: true`, `target_absent: true`, `unrelated_files`, and `unrelated_tasks`. Declare 1–32 unrelated files with `path`, `size`, and `sha256`, and 0–8 unrelated tasks with `name` and `xml_sha256`. Task hashes cover UTF-8 `Export-ScheduledTask` output. These exact fixtures remain outside the installation subtree.
- `authorization` contains `candidate_sha`, `fixture_id`, `installation_id`, `manifest_sha256`, `destination_sha256`, `before_state_sha256`, `bootstrap_sha256`, `connection_sha256`, `expected_host_sha256`, `scope: "host-install-run-remove"`, and `launch: true`.
- Optional `ssh_config` and `publish_viewport` retain their baseline meanings.

Authorization's `manifest_sha256` binds raw manifest bytes. Other authorization digests bind the corresponding complete object using compact, key-sorted UTF-8 JSON with Python's default ASCII escaping. `destination_sha256` hashes `installation`; `bootstrap_sha256` hashes the whole bootstrap pin, not just executable bytes. For a loaded object `value`, the digest input is `json.dumps(value, sort_keys=True, separators=(",", ":")).encode()`. Preserve the exact candidate and grant; the installer does not accept the baseline protected-environment placeholder.

The planner's `manifest_sha256` is a separate digest of the typed runtime manifest. The proof validates every field before reconstructing that representation. Before each setup invocation it rechecks the remote bootstrap, manifest, and artifact hashes. SSH uses a short remote command and streams a UTF-8 script bounded to 128 KiB through stdin. Private command receipts retain that input alongside stdout and stderr.

```sh
python3 scripts/onboarding_proof.py host-install \
	--candidate "$CANDIDATE_SHA" \
	--candidate-checkout "$CANDIDATE_CHECKOUT" \
	--operator-config "$INSTALL_OPERATOR_CONFIG" \
	--output "$INSTALL_PROOF_OUTPUT" \
	--execution local
```

Require the baseline outcomes plus `install-inspect`, `install-preview`, `install-apply`, `install-target`, `install-repeat`, `remove-preview`, `remove-apply`, `remove-repeat`, and `fixture-preserved`. The proof checks the before-state, inspects and previews, installs, fetches the generated target, runs readiness and the real Scenario, verifies exact recovery, repeats installation, previews and repeats removal, then compares unrelated fixtures. No target paths are hand-edited.

Retain private CLI receipts and original target snapshots after failure. Recover a lost setup response through fresh `setup status` using the recorded installation and operation IDs. If cancellation is needed, `setup stop --apply` must name the observed execution token. A cancellation receipt alone does not prove cleanup. Remove only an installation whose ownership is known and whose Run and installer execution are proven settled. Missing Run authority, unknown process-tree cleanup, or unsettled task mutation must retain the runtime and pending setup fence for recovery. Successful removal retains the shared authority skeleton, receipt tombstone, execution records, and exported target.

Recovery polls an admitted execution whose process identities have not appeared yet. It keeps the original token, request hash, and deadline, then pins each process identity when observed. A later replacement or disappearance fails recovery. If cancellation is followed by a settled execution whose fence remains held, recovery requests exact-token reconciliation and observes status again within the same bounded budget.

The observation budget starts before the first status request. Each status or stop receives the time remaining from that 15-second budget; expiry prevents another request. Settling an interrupted local command can still take the separate existing cleanup grace, so the budget is not a total shutdown-time guarantee.

This sequence does not inject installation interruption, drop SSH deliberately, or exercise removal refusal during a live or kept Session. Those remain explicit `not_exercised` entries; local failure tests do not prove their native behavior. Native acceptance must cover those cases separately before closing the installation issue.

## Enable the hosted gate

Hosted execution currently fails preflight with `hosted-recovery-retention-unavailable`, before any candidate or host command. The controller's private original Run claim and Session pin must survive loss of an ephemeral runner when cleanup is unknown. Public outcome/viewport uploads cannot retain those private records. A private durable retention mechanism and its recovery procedure are required before this guard can be removed. Environment approval alone does not satisfy that prerequisite.

Treat workflow preparation and infrastructure enrollment as separate operations. Adding the workflow does not authorize access to a host.

The workflow is `Windows onboarding proof`, with jobs `baseline`, `named-target`, and `host-install`. Named-target runs only after baseline succeeds, on a separate fresh controller against the same authorized fixture. Host-install waits for the earlier jobs to finish and shares workflow-level host serialization. Configure `windows-onboarding-approval` with a required reviewer and restrict it and `windows-onboarding-host` to trusted main. Keep baseline host credentials only in `windows-onboarding-host`. Ordinary pull-request jobs must not receive them. GitHub documents [environment protection and branch restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments); Tailscale documents [ephemeral CI access](https://tailscale.com/kb/1586/secure-github-runners).

Host-install uses a separate protected `windows-onboarding-installer` environment and `ONBOARDING_INSTALL_OPERATOR_CONFIG` secret binding the exact candidate. Its current job checks out only the trusted driver and invokes the blocked preflight. It does not provision SSH/Tailscale credentials or check out candidate code. Durable private recovery retention, approved fixture and bundle preparation, and a separately reviewed live job are prerequisites for enabling hosted installation. The job's existence is not installation proof.

Configure these environment secrets:

- `ONBOARDING_OPERATOR_CONFIG`. Private schema above, with dedicated fixture `windows-onboarding-prepared-v1` in state `prepared`. Set `authorization.candidate_sha` to `protected-environment-approval`; the approved workflow substitutes the immutable candidate SHA.
- `ONBOARDING_SSH_KEY`, `ONBOARDING_KNOWN_HOSTS`, and `ONBOARDING_SSH_HOSTNAME`. Dedicated SSH access and preverified host trust.
- `ONBOARDING_TS_CLIENT_ID` and `ONBOARDING_TS_CLIENT_SECRET`. Ephemeral controller access scoped to `tag:blender-box-onboarding` and the target's SSH port.

The workflow accepts dispatches by `BramVR` on `main`, with a full commit SHA. A retry requires a fresh dispatch and approval. Baseline and named-target fixtures must already contain the exact candidate. Installation proof uses a separate dedicated fixture and grant. These gates still require maintainer participation.

Before enrollment, review the exact environment settings, authorized candidate policy, SSH account/key scope, Tailnet tag and SSH-only network permission, and fixture mutation inventory. Use a fresh hosted controller for each job. Do not enroll a shared Windows desktop as an unrestricted self-hosted runner.

Dispatch only an explicitly authorized full candidate SHA through the trusted main workflow. Keep the trusted driver revision separate from the candidate checkout and record both revisions. An untrusted branch, malformed candidate, missing configuration, or unauthorized retry must fail before host access. Do not substitute a branch name for the accepted SHA.

Upload only the runner's public projection and explicitly permitted validated viewport. Never upload private output, raw diagnostics, target documents, credential files, or an arbitrary Evidence Bundle glob. A viewport capture proves the scene, not Blender window chrome or the Windows desktop.

The baseline accepts noninterlaced 8-bit RGB or RGBA PNG captures with valid pixel data and bounded numeric color or resolution metadata. This includes Blender's resolution-only EXIF layout and zero image origin. Other EXIF layouts, free-form metadata and unsupported encodings fail validation. Original capture bytes and hashes are preserved.

Evidence validation and cleanup are separate outcomes. A rejected or missing retained image fails the proof while preserving cleanup facts established by matching public status and stop receipts.

Local receipt or process setup failures still trigger graceful command cancellation and exact process-group cleanup. If cleanup cannot be verified, the runner reports it as unknown and stops further recovery commands.

Inspect the actual hosted job conclusion and returned receipts. A missing, skipped, cancelled, fake-only, or merely local gate leaves the required proof incomplete. Local success does not establish environment policy or hosted reachability.

## Extend the proof

Reuse `scripts/onboarding_proof.py` for the expected-host assertion, bundle integrity, complete Run authority comparison, and cleanup assertions. Keep feature-specific Scenario checks separate from those generic assertions. Run the existing baseline fixture when a later job needs to prove the Run path after its feature operation.

The shared outcome vocabulary covers host preparation, pairing, readiness, Scenario execution, evidence, recovery, and cleanup. Baseline requires preparation, readiness, Scenario, evidence, recovery, and cleanup. It does not claim pairing or fixture reset. Named-target and host-install add the feature outcomes above. A later `pair-and-run` job needs its own outcomes and real hosted proof.

Prepared and unpaired starting states require an operator-owned restoration mechanism with exact test-resource ownership. Preserve operator SSH access, credentials, users, Blender preferences, Python, and unrelated applications. Do not implement restoration by deleting a root prefix or registering over an unknown task. Until authorized repeatable restoration and automatic trusted execution are proven, dependent onboarding work remains blocked or requires maintainer participation.

Run the host-free repository gate before live proof:

```sh
./scripts/ci all
```

The default suite verifies workflow authorization, absent configuration, failure recovery, wrong-host rejection before mutation, and evidence validation with fakes. Windows is the first live platform; these tests do not imply Linux or macOS onboarding coverage.
