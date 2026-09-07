---
summary: Windows installation owns an immutable runtime and task through a durable receipt.
read_when:
  - Changing setup, runtime packaging, installation recovery, or removal.
  - Extending host onboarding or maintenance fencing.
---

# Windows installation ownership

## Decision

Use a host-local Windows installer with one durable receipt per installation. A portable reconciler owns the plan, manifest, progress, and removal rules. Windows effects own identity, physical paths, ACLs, interpreter inspection, and Scheduled Tasks. The common CLI selects only implemented platforms. It does not encode Windows setup phases into target configuration.

The installation identity and operation identity are distinct. Install preview, apply, and retries share one operation identity. Removal starts a new operation identity and retains it across retries. A plan digest binds the intended operation; it does not prove ownership of existing resources. An installation receipt records that ownership before mutation. Target schema version 2 and the original Run authority journal retain their existing meanings.

## Runtime

A versioned manifest names exactly three bounded, local artifacts with sizes, SHA-256 digests, and source provenance. They are the Windows host executable, native daemon launcher, and compatible pure-Python daemon wheel. There is no package download or dependency resolution during installation.

The installer uses explicitly selected external CPython and Blender installations. It hashes prerequisite files with a separate 2 GiB bound instead of applying the 64 MiB runtime artifact limit. It creates a minimal private Python environment from a supported Windows venv redirector and extracts the validated wheel into its site-packages. The plan records generated files and external interpreter inputs. No global package installation or activation script is needed.

Python inspection executes only after a bounded, read-only audit of its imported DLL, runtime tree, and startup lookup parents. Its home directory is an import root, so the audit includes arbitrary package subdirectories and bytecode caches. Only the excluded global `Lib/site-packages` contents are skipped. Isolated mode suppresses registry search paths but does not suppress launcher environment overrides or `._pth` files; setup removes those overrides and refuses redirector files. Missing startup markers require trusted creation authority at their lookup parents. This includes the out-of-tree build-marker lookup documented in [CPython issue 151544](https://github.com/python/cpython/issues/151544). Unsafe shared-parent layouts refuse inspection instead of changing external permissions.

Both ordinary and instrumented CPython build-marker locations are checked before Python can classify its build. Setup and the broker remove `_PYTHON_PROJECT_BASE` because `sysconfig` reads it despite isolated mode. Native children use their executable directory as the working directory and an OS-reported System32-only `PATH`, so the [Windows DLL loader](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order) cannot fall back to an inherited directory. The same OS lookup supplies PowerShell's absolute executable path and replaces inherited Windows-root environment values. PowerShell resets module discovery to its built-in modules before invoking cmdlets, so inherited module directories cannot supply the trust checks.

The native launcher invokes adjacent private Python with isolation and bytecode writes disabled. Ordinary daemon children must still resolve the private package through `sys.executable`. A parent-only import-path patch cannot meet that requirement. Installation checks the required daemon capabilities without launching Blender.

CPython's regular Windows venv template moved from `Lib/venv/scripts/nt/python.exe` in [3.11](https://github.com/python/cpython/blob/v3.11.15/Lib/venv/__init__.py#L237-L261) and [3.12](https://github.com/python/cpython/blob/v3.12.10/Lib/venv/__init__.py#L264-L288) to `venvlauncher.exe` in [3.13](https://github.com/python/cpython/blob/v3.13.7/Lib/venv/__init__.py#L295-L328). Supported layouts must be selected explicitly and checked on the host. Debug, free-threaded, build-tree, and already virtualized interpreters need a separate recipe.

The supplied daemon package version alone is insufficient provenance. Compatible and incompatible builds can share a version. A patched artifact needs its source revision, patch digest, recipe digest, exact wheel hash, and the installed capability result.

## Authority and interruption

Installation keeps the existing work root as the shared Host Lock namespace. It takes the operation lock and tries the launch lock once. It cannot wait for launch while holding operation because Run startup may need operation again to publish its Session identity. Busy or ambiguous state refuses maintenance.

Each applied operation runs through a finite native keeper started from the verified external bootstrap. The keeper owns one installer worker in an unnamed Windows Job, including target publication and the worker's child probes. It has its own bounded deadline, independent of the waiting CLI or SSH connection. The worker cannot begin mutation until its exact process creation identity and immutable execution request have been recorded. The keeper must prove it escaped every caller Job before admitting the worker: [nested Job breakaway](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs) can stop at a restrictive ancestor, and [IsProcessInJob](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob) with a null Job handle checks membership in any Job.

Logical operation identity remains stable across installation retries. Each physical execution has a fresh internal token, request digest, deadline, and predecessor binding. Immutable execution records live below the same state root and remain after removal. A durable pending setup fence excludes new Runs and unrelated maintenance until exact execution cleanup is established. The admitted worker receives an exception only for its own matching fence. Existing Run status and exact Session stop remain available.

Atomic runtime and execution-record publication stages bytes in the validated state root, outside the exact runtime and execution inventories. Receipt publication continues staging beside its receipt. Abrupt process exit can leave staging files; they grant no authority and remain untouched. Strict readers still reject unknown entries inside their inventories. A directory created before its first durable receipt or request remains an unowned ambiguity; staging placement does not authorize adoption.

Fresh setup status validates execution records and the keeper's process creation identity. A live keeper is not evidence of progress. Exact setup stop publishes an immutable cancellation request; only the keeper's retained Job handle can terminate its process tree. Cancellation requested and process-tree exit are separate facts. Terminal evidence must precede release of the matching pending setup fence. If a crash interrupts that release, exact stop can reconcile the already settled fence. The public result reports whether the fence is held or released. Status never repairs records or releases authority.

Repeated apply observes an unsettled execution or returns a successful terminal result after checking current installation state. A partial operation can resume only after the previous execution's tree exit is proven and fresh admission checks pass. The new execution token prevents an old stop request from cancelling that retry. Stop cancels one execution; it does not revoke the logical operation or prohibit a later authorized apply.

Keeper loss before durable tree-exit evidence remains unknown. Kill-on-close and absent process IDs do not reconstruct missing descendant evidence. Preserve the pending fence, installation receipt, runtime, and target. Likewise, tree exit alone does not prove a Task Scheduler mutation already submitted through COM has settled. Unresolved task mutation remains separate from process cleanup and cannot be cleared merely because a fresh task lookup reports absence.

A failed native startup can settle without worker identity only when the keeper records explicit proof that no worker process was created. That `not-started` execution may resume with a new token after fresh admission checks. Missing ownership records never establish this state.

Native setup probes own a separate, unnamed Windows Job with kill-on-close. Windows 10 or later assigns each probe to that Job atomically at process creation through `PROC_THREAD_ATTRIBUTE_JOB_LIST`. Only its standard input and output handles are inherited. Owned command roots start detached and suspended; exact root identity, Job-member collection, and any admission gate are ready before resume. This authority covers only the probe tree created by setup and never an existing Session. Atomic assignment avoids the orphan interval between creating a process and assigning it to a Job, as described by [Microsoft](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812).

Each invocation retains at most 256 exact process handles, including its original root, and consumes at most 2,048 Job completion messages. Notifications supply PID discovery hints; accepting a handle requires creation identity and membership in that exact Job. Handles remain open through the final cleanup decision. One final complete membership capture, collector shutdown, one Job termination, all process waits, and pipe completion share a single five-second cleanup deadline. Known cleanup requires every retained handle to signal, an empty Job, a final lifetime process count equal to the unique retained membership, and no collection or API fault. A missing member, failed open, partial list, count decrease, or exhausted bound leaves cleanup unknown. Job accounting and completion notifications alone cannot prove physical process exit.

Cancellation, output overflow, a nonzero root exit, and descendants left at normal root exit still fail the operation. Complete cleanup proof may nevertheless record tree exit and permit the existing fence-release path. Failed pipe I/O, incomplete drain, or any failed cleanup check suppresses that acknowledgment.

This contract covers the fixed, reviewed installer workloads. It assumes ordinary Win32 child association completes before its creating process finishes and that the lifetime process count does not wrap. Collection limits and deadlines do not prove either assumption for arbitrary workloads. Lost notifications can prevent exact capture of a fast child and leave a completed operation's cleanup unknown; normal installer availability therefore needs real nested-worker PowerShell, Python, and daemon proof. A stronger child-handle transfer protocol would be a separate design. See Microsoft's [Job accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information), [completion notifications](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port), and [process termination and waits](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess) contracts.

The installation owns one runtime child and its exact marked task. It never adopts an existing file or task because the path, name, hash, or definition happens to match. Repeated operations reload the durable receipt and compare immutable intent and observed state. Incomplete publication remains visible as partial or conflicting state.

The same Windows SID owns setup and the interactive task, within the existing [same-user boundary](0002-slice-0-windows-identity.md). Physical-path and ACL checks reject untrusted replacement authority and reparse points. These checks do not defend against arbitrary concurrent code under that same SID.

## Removal

Removal requires the installation receipt and explicit apply. It refuses active Run authority, pending requests, unsettled receipts, nonempty Run directories, and a busy task or launch fence. It never stops a process as a side effect.

Task removal requires the recorded marker and exact definition. File removal requires the recorded inventory and current file hashes. Removal proceeds leaf first and preserves modified files, unknown descendants, and replacement tasks. It uses Run authority, task state, and ownership records without executing the runtime being removed. Missing external Python or partially deleted runtime files therefore do not prevent exact removal. It retains shared authority directories, both lock files, installation receipts, and tombstones. Retrying removal confirms absence without gaining authority over later replacements.

Target export or saving is the final step inside the owned worker. Its result remains separate from installation success. Destinations inside the setup state root are rejected before installation, including a configured target store inside that root. A publication error does not undo a successfully installed runtime. Original target snapshots and Run recovery records must remain available until all Runs settle.

## Alternatives and consequences

Extending the old SSH PowerShell deployment would duplicate receipt and recovery policy at the transport boundary. Host-local reconciliation keeps that policy testable with local files and fake Windows effects. A verified bootstrap and locally available bundle are prerequisites; automated SSH bootstrap is not part of this change.

The legacy apply path used task replacement without installation ownership. It now refuses before transport. Its offline preview remains available. Existing installations need explicit operator handling; there is no automatic adoption or migration.

Future account-scoped SSH preparation belongs behind the Windows setup operation boundary. It requires its own typed request, ownership, inspection, reversal, and explicit authorization. It does not belong in a target fingerprint or Run journal.

Local tests and Windows cross-compilation cannot prove native venv behavior, ACLs, Scheduled Tasks, or Blender execution. Acceptance requires the exact candidate's separately authorized `host-install` proof, a real Scenario, verified evidence and recovery, and unrelated fixture preservation. Hosted execution remains blocked until private recovery authority has durable retention.
