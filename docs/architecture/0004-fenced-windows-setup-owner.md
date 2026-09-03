---
summary: Windows setup programs run only through a fenced daemon-owned process tree.
read_when:
  - Changing Windows setup apply, setup recovery, setup cleanup, or blendersessiond setup-owner calls.
---

# Fenced Windows setup owner

## Status

Accepted for slice 0.

## Problem

An SSH process cannot safely own a detached Windows setup process. If the SSH response is lost or the client is cancelled, a direct PowerShell launch can outlive the caller without a durable process identity. Name and PID matching cannot distinguish that process from unrelated work or a reused PID.

## Decision

`windows setup --apply` provisions a private `setup-owner` tree under the declared work root and stages the setup program at a path derived from a random 256-bit Setup Attempt ID. The client sends `blendersessiond setup-owner launch` an immutable request containing that Attempt ID, a separate random Launch ID, a deadline, the `windows-setup-owner-v1` revision, and the exact script size and SHA-256.

Every later status or stop call carries the Attempt ID, Launch ID, and request SHA-256. The daemon-visible request deadline is the earlier of the fixed setup limit and the caller deadline. The client accepts only strictly shaped JSON with the same fence, repeats status reconciliation until that deadline, and gives cancellation a separate bounded context to repeat the same exact stop until cleanup is known or its cleanup deadline expires. It never discovers or kills a process by name or PID.

Setup succeeds only when the daemon reports `process_succeeded`, exit code zero, untruncated output, and `tree_gone`, and the client strictly validates the nested setup result. Once `tree_gone` is proven, the client removes the exact staged binary and script before returning success or a setup-result failure. If ownership or cleanup remains unverified, setup returns that failure and leaves the remote files untouched for operator recovery.

## Consequences

- A lost SSH response does not create a second setup process.
- A stale client cannot inspect or stop a replacement attempt.
- The daemon's launch receipt records the keeper and root process creation identities; Blender Box treats those as evidence, not as authority for direct process operations.
- `windows check` requires the setup-owner capability and validates the private state tree after setup.
- The operator must provision a compatible `blendersessiond`; Blender Box does not install or upgrade it.
