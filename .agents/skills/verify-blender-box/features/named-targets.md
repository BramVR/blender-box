# Named targets

Use the public CLI to import a target into isolated user-local configuration, select it by name, and verify that replacement cannot redirect recovery.

## Local checks

- Build the actual client and use an absolute task-owned `BLENDER_BOX_CONFIG_DIR`.
- Import a synthetic flat schema 1 Windows file with `targets import NAME --file PATH --json`. Inspect `targets list --json` and `targets show NAME --json`; the latter contains a schema 2 Windows target.
- Change or remove the source file and confirm the imported copy is unchanged.
- Require explicit `--replace` for a collision. Unsafe names, unknown platforms, and both selector flags fail locally.
- Exercise `windows setup` preview by name. It must make no SSH connection.
- Use recording fake SSH for public status/stop mismatch tests. Require the original-target error and zero transport invocations. A nonzero exit alone is insufficient.

These checks do not prove a Windows Scenario, real evidence transfer, or cleanup.

## Required live proof

Read `docs/windows-onboarding-proof.md` and the main verification skill before any live work. Host access, setup, trusted candidate execution, and workflow dispatch require their existing explicit authorization.

Run `scripts/onboarding_proof.py named-target` with the same candidate, operator configuration, output, and execution arguments as the baseline command. The runner uses the shared expected-host, Scenario, evidence, recovery, and cleanup assertions.

Require import and named selection, a real Scenario, fresh-process named recovery, and replacement refusal for both status and stop. The negative phase uses a local SSH/SCP tripwire, so it must prove that no transport process was invoked for the replacement. The runner restores matching original configuration before final exact recovery.

Read the actual receipts and retained files. Preserve candidate commit, binary hashes, Run ID, full exposed claim, exact Session, remote/local hashes, capture provenance, validation, and all four cleanup facts. Do not publish target documents, configuration roots, aliases, operator paths, or private receipts.

The required hosted job is `Windows onboarding proof` / `named-target`, serialized after `baseline`. Missing, skipped, failed, fake-only, or merely local proof leaves this requirement incomplete.

Hosted execution currently refuses preflight with `hosted-recovery-retention-unavailable`. Private original Run authority must survive an ephemeral runner's loss before the hosted guard can be removed; public artifacts cannot supply it.
