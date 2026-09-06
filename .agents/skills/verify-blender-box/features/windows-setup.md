# Owned Windows setup

Use the public host-local `setup inspect`, `setup install`, and `setup remove` commands. Read `docs/windows-installation.md` and `docs/architecture/0004-windows-installation-ownership.md` before proof.

## Preconditions

- Explicit installation and removal authorization for an exact dedicated fixture. Baseline Run authorization is insufficient.
- Verified physical hostname, same Windows SID, logged-in desktop, supported external Blender/Python, and no unknown active Run or Session.
- Verified external bootstrap, candidate host/broker executables, compatible daemon wheel, manifest, and source/patch/recipe hashes.
- Shared Host Lock namespace preserved. Existing operator runtime and tasks remain nondisposable.
- Retain private receipts, generated original target, and local Run authority outside the runtime being removed.

## Observable coverage

- Inspect and install preview report identity, selections, prerequisites, exact inventory, plan digest, and conflicts without creating files or tasks. Ambiguous Blender discovery requires explicit selection.
- Explicit install uses the reviewed installation identity and plan digest. Require installed state, deployed hashes, required capabilities, exact limited-rights task, and generated target schema version 2. No Blender launch during setup.
- Export or save failure remains distinct from installed state. Existing output files or names remain unchanged.
- Read-only `windows check` passes using the generated target. A real baseline Scenario returns verified viewport evidence, then fresh status/stop/status agree with original Run and exact Session authority.
- Repeated installation retains the same ownership and task. Interrupted publication either converges from its receipt or reports exact partial/conflicting state.
- Active Run or launch state refuses removal without stopping anything. Recover only through the original public Run/Session authority.
- Removal preview changes nothing. Applied removal verifies recorded task and file identities/hashes, removes owned task before runtime, and preserves modified files, unknown descendants, unrelated fixtures, Blender, Python, and settings.
- Repeated removal confirms absence. Shared root, authority directories, lock files, receipts, and tombstones remain. Replacements at old paths are not owned.

## Driving proof

Use `scripts/onboarding_proof.py host-install` with the separate private installation configuration in `docs/windows-onboarding-proof.md`. The fixture must already provide the verified external bootstrap and pinned bundle; proof does not bootstrap by hidden uploads. Keep failed or unknown cleanup visible.

Require the actual `Windows onboarding proof` job `host-install` on the exact candidate. Local tests and cross-builds do not prove Windows installation. Hosted execution stays blocked until private recovery authority survives controller loss. Do not remove the retention guard to obtain a passing badge.

## Legacy behavior

`windows setup --target TARGET --host-binary EXE --json` remains an offline binary preview. Adding `--apply` must fail with `legacy-setup-unowned` before SSH. Legacy resources have no installation receipt; no automatic migration or adoption is permitted.
