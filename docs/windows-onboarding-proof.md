---
summary: Run Windows baseline and named-target proof with private authorization and verified evidence.
read_when:
  - Running or extending Windows onboarding proof.
  - Configuring trusted live CI or preparing onboarding fixtures.
---

# Run Windows onboarding proof

Use this guide to prove a candidate through the existing Windows Run path. The baseline creates a cube in a fresh Blender Session, returns a viewport Evidence Bundle, reconnects, and verifies exact cleanup. It does not install Blender or the daemon, enroll SSH or Tailscale, pair a host, or reset an installation.

## Prepare the private configuration

Select an owned Windows desktop with a logged-in interactive user, a compatible daemon, and an existing target profile. The SSH user and interactive task must resolve to the same SID. Preserve the host's existing shared Host Lock root; creating another root is not a way to bypass activity on the desktop.

Record the expected hostname, Windows build, Blender version, interactive identity SID, daemon executable hash, and exact target in a private operator document outside the repository. Retain the daemon source revision, any patch digest, wheel hash, installed-source verification, and Python version beside it. A package version alone does not prove the required `blender-box-v1` and `typed-call-error-reason` capabilities.

Use schema version 1 with these fields:

- `target`. The complete target JSON from the [target profile guide](../README.md#create-a-target-profile). Flat target schema version 1 and nested Windows version 2 are accepted; the operator document itself remains schema version 1.
- `expected_host`. `hostname`, `windows_build` (Windows `BuildNumber`, such as `19045`), `blender_version` (the executable's exact `ProductVersion`), `identity_sid`, and `daemon_sha256`.
- `fixture`. Its exact `id`, `kind` (`shared-existing` or `dedicated`), and `state` (`prepared`). These declarations do not create ownership or authorize reset.
- `authorization`. The exact `candidate_sha`, matching `fixture_id`, `launch: true`, and `setup: null` when setup changes are not permitted.
- `ssh_config`. Optional absolute path to a private SSH configuration. Use strict host-key verification and an existing trusted host key. The runner keeps this configuration separate from your normal SSH files.
- `publish_viewport`. Optional boolean, default `false`. Explicitly permit publication only after reviewing the baseline capture policy.

Authorize setup only after reviewing the exact product setup scope. Its `setup` object binds `candidate_sha`, canonical `target_sha256`, `prior_host_sha256`, and `scope: "windows-setup-binary-task-acls"`. The scope includes publishing the host binary, registering the declared Scheduled Task, and applying managed ACLs. It does not authorize runtime installation or fixture reset. A prior hash of `null` is appropriate only when the expected destination is absent.

The setup target hash covers the supplied target document, before version normalization. Keep it distinct from the product's normalized recovery fingerprint. Re-encoding an operator target from version 1 to version 2 requires a new setup authorization hash.

Keep secrets, resolved host details, and raw check output private. Do not copy a previous task's authorization into a new candidate configuration. Readiness and a matching path or task name do not establish ownership.

## Run the candidate locally

Use a macOS or Linux controller with Python 3.12, the repository's Go version, and a clean candidate checkout. Windows controllers are unsupported by this proof runner; Windows is the remote Blender host. Set the private configuration's permissions to `0600`. Supply the full commit SHA, private configuration, and a fresh proof-output directory outside the checkout or under its ignored `.blender-box/` directory. The output's parent must exist.

```sh
python3 scripts/onboarding_proof.py baseline \
	--candidate "$CANDIDATE_SHA" \
	--candidate-checkout "$CANDIDATE_CHECKOUT" \
	--operator-config "$BLENDER_BOX_PROOF_CONFIG" \
	--output "$PROOF_OUTPUT" \
	--execution local
```

The runner builds both candidate executables. It verifies the expected host before mutation, rejects unrelated Blender activity or a Host Lock, and requires the installed host binary to match the candidate. A mismatch needs the exact setup authorization above. It then runs the public check, Scenario, status, stop, and final status commands.

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

## Enable the hosted gate

Hosted execution currently fails preflight with `hosted-recovery-retention-unavailable`, before any candidate or host command. The controller's private original Run claim and Session pin must survive loss of an ephemeral runner when cleanup is unknown. Public outcome/viewport uploads cannot retain those private records. A private durable retention mechanism and its recovery procedure are required before this guard can be removed. Environment approval alone does not satisfy that prerequisite.

Treat workflow preparation and infrastructure enrollment as separate operations. Adding the workflow does not authorize access to a host.

The required workflow is `Windows onboarding proof`, with jobs `baseline` and `named-target`. Named-target runs only after baseline succeeds, on a separate fresh controller against the same authorized fixture. Configure `windows-onboarding-approval` with a required reviewer and restrict both it and `windows-onboarding-host` to the trusted main branch. Keep host credentials only in `windows-onboarding-host`. Ordinary pull-request jobs must not receive them. GitHub documents [environment protection and branch restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments); Tailscale documents [ephemeral CI access](https://tailscale.com/kb/1586/secure-github-runners).

Configure these environment secrets:

- `ONBOARDING_OPERATOR_CONFIG`. Private schema above, with dedicated fixture `windows-onboarding-prepared-v1` in state `prepared`. Set `authorization.candidate_sha` to `protected-environment-approval`; the approved workflow substitutes the immutable candidate SHA.
- `ONBOARDING_SSH_KEY`, `ONBOARDING_KNOWN_HOSTS`, and `ONBOARDING_SSH_HOSTNAME`. Dedicated SSH access and preverified host trust.
- `ONBOARDING_TS_CLIENT_ID` and `ONBOARDING_TS_CLIENT_SECRET`. Ephemeral controller access scoped to `tag:blender-box-onboarding` and the target's SSH port.

The workflow accepts dispatches by `BramVR` on `main`, with a full commit SHA. A retry requires a fresh dispatch and approval. Setup authorization still binds an exact candidate, target, and prior binary hash; it must be prepared separately when the installed binary differs. This gate therefore still requires maintainer participation.

Before enrollment, review the exact environment settings, authorized candidate policy, SSH account/key scope, Tailnet tag and SSH-only network permission, and fixture mutation inventory. Use a fresh hosted controller for each job. Do not enroll a shared Windows desktop as an unrestricted self-hosted runner.

Dispatch only an explicitly authorized full candidate SHA through the trusted main workflow. Keep the trusted driver revision separate from the candidate checkout and record both revisions. An untrusted branch, malformed candidate, missing configuration, or unauthorized retry must fail before host access. Do not substitute a branch name for the accepted SHA.

Upload only the runner's public projection and explicitly permitted validated viewport. Never upload private output, raw diagnostics, target documents, credential files, or an arbitrary Evidence Bundle glob. A viewport capture proves the scene, not Blender window chrome or the Windows desktop.

The baseline accepts noninterlaced 8-bit RGB or RGBA PNG captures with valid pixel data and bounded numeric color or resolution metadata. Free-form metadata and unsupported encodings fail validation.

Inspect the actual hosted job conclusion and returned receipts. A missing, skipped, cancelled, fake-only, or merely local gate leaves the required proof incomplete. Local success does not establish environment policy or hosted reachability.

## Extend the proof

Reuse `scripts/onboarding_proof.py` for the expected-host assertion, bundle integrity, complete Run authority comparison, and cleanup assertions. Keep feature-specific Scenario checks separate from those generic assertions. Run the existing baseline fixture when a later job needs to prove the Run path after its feature operation.

The shared outcome vocabulary covers host preparation, pairing, readiness, Scenario execution, evidence, recovery, and cleanup. Baseline requires preparation, readiness, Scenario, evidence, recovery, and cleanup. It does not claim pairing or fixture reset. Named-target additionally requires the four target outcomes above. Later `host-install` and `pair-and-run` jobs must supply their own required feature outcomes and real hosted proof.

Prepared and unpaired starting states require an operator-owned restoration mechanism with exact test-resource ownership. Preserve operator SSH access, credentials, users, Blender preferences, Python, and unrelated applications. Do not implement restoration by deleting a root prefix or registering over an unknown task. Until authorized repeatable restoration and automatic trusted execution are proven, dependent onboarding work remains blocked or requires maintainer participation.

Run the host-free repository gate before live proof:

```sh
./scripts/ci all
```

The default suite verifies workflow authorization, absent configuration, failure recovery, wrong-host rejection before mutation, and evidence validation with fakes. Windows is the first live platform; these tests do not imply Linux or macOS onboarding coverage.
