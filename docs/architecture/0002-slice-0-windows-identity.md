---
summary: Slice 0 uses one Windows identity for SSH control and the interactive task.
read_when:
  - Changing Windows identities, ACLs, staging, Scheduled Tasks, or the same-user threat boundary.
---

# Slice 0 Windows identity boundary

## Status

Accepted for slice 0.

## Problem

The controller stages immutable payload files over SSH, while the interactive Scheduled Task consumes them and creates runtime evidence. Supporting different Windows identities safely requires more than directory ACLs: staging needs controller-only temporary storage, no-follow or handle-relative writes, atomic publication with per-subtree ACLs, and equivalent protection for later controller reads and cleanup. Granting a distinct task user inherited Modify rights on the shared Run tree creates junction-replacement races and does not meet that contract.

## Considered designs

Design A supports separate controller and task identities. It adds Windows-specific filesystem primitives and publishes each Run with immutable payload/request subtrees plus narrowly writable runtime/evidence subtrees. This can be safe, but it is a separate product slice with new OS-specific code and recovery states.

Design B requires the authenticated SSH controller SID and interactive task SID to be identical. Setup and read-only inspection both fail closed on a mismatch. The existing ACLs still constrain unrelated principals, while a concurrent process under the same SID remains inside the documented same-user filesystem threat boundary.

## Decision

Slice 0 uses Design B. One declared Windows identity owns controller writes and the interactive task. This keeps the public target contract small and makes its actual isolation boundary explicit instead of presenting incomplete split-user isolation.

Separate identities remain deferred until Design A is implemented and proven as one coherent storage boundary. Adding it requires controller-only staging, reparse-safe path operations, immutable published payload and request paths, narrowly writable runtime paths, exact cleanup, default fake coverage, and real Windows proof.

## Consequences

- `windows setup` verifies SID equality before applying changes.
- `windows check` reports failure unless the SSH and console/task identities resolve to the same SID.
- Setup does not grant a distinct interactive identity access to managed paths or task execution.
- Existing targets that name different users are rejected before a Run.
