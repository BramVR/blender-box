# Agent notes

- Commits: use `committer`; stage only named paths; Conventional Commits.
- Product name: Blender Box. Binary and config prefix: `blender-box`.
- Default target: owned Windows host over a safe SSH config alias. Tailscale supplies reachability for now.
- Do not put private hostnames, Tailnet addresses, Windows users, SSH keys, credentials, or operator paths in repo config, docs, tests, or fixtures.
- SSH owns control and file transfer. Never expose or forward the Blender MCP add-on port.
- Windows OpenSSH is not an interactive GUI launcher. Start Blender through the declared passwordless Scheduled Task for a logged-in interactive user.
- `blendersessiond` remains same-machine and owns Blender lifecycle, health, raw calls, and process-tree stop.
- Shared Windows Host Locks must fence every run by Run ID, request identity, deadline, and exact daemon Session identity.
- Setup commands are read-only by default. Remote writes require an explicit apply flag.
- Scenario scripts and consuming repos own Blender-domain correctness. Core validators stay generic.
- Default tests use fake SSH, Scheduled Task, daemon, and Blender boundaries. Live behavior needs opt-in real Windows Blender proof.
- Update the research brief when implementation decisions replace its proposals.

