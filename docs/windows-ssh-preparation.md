---
summary: Inspect an installed Windows host and review the exact proposed account-scoped SSH preparation.
read_when:
  - Preparing Windows SSH access for pairing.
  - Reviewing an SSH preparation plan or diagnosing a refused preview.
---

# Preview Windows SSH preparation

Use this guide as the operator of an owned Windows desktop with an existing Blender Box installation. The preview reads the selected installation and local OpenSSH state, then describes the proposed configuration and account-scoped authorization source. It creates no files, changes no service or firewall rules, and grants no permission to apply the proposal.

Run the verified bootstrap in an elevated Windows terminal under the installed account. That account must also own the logged-in desktop. Supply an explicit request file:

```powershell
& $Bootstrap setup ssh --request $SSHPreparationRequest --json
```

The schema-1 request names the Windows platform, installed state root and installation ID, a fresh operation ID, the selected account, and a UTC deadline within five minutes. Its connection scope includes the exact hostname and port, login user, local listening addresses, remote CIDR prefixes and firewall profiles. Supply one to eight independent control accounts. Account and login names must match and use canonical lowercase spelling; selector lists must be sorted and unique. Use operator-verified values. Keep the request and returned plan private; they contain host paths, account identities and access policy.

Build the request from the installation receipt and your verified connection selections. The variables below name those selections and a private request-file destination. This writes only that local request file; it does not apply SSH changes.

```powershell
$Request = [ordered]@{
    schema_version = 1
    platform = 'windows'
    installation_id = $InstallationID
    operation_id = 'bbxo_' + [guid]::NewGuid().ToString('N')
    state_root = $StateRoot
    account = $WindowsUser.ToLowerInvariant()
    connection = [ordered]@{
        hostname = $Hostname
        port = $Port
        login_user = $WindowsUser.ToLowerInvariant()
        local_addresses = @($LocalAddresses)
        remote_prefixes = @($RemotePrefixes)
        firewall_profiles = @($FirewallProfiles)
    }
    control_accounts = @($ControlAccounts)
    deadline = [DateTime]::UtcNow.AddMinutes(4).ToString('o')
}
[IO.File]::WriteAllText($SSHPreparationRequest, ($Request | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
```

Require `state: previewed` and an empty `problems` list. A refusal returns a nonzero exit and no plan. Invalid request files fail before native inspection. `--apply` is rejected before reading the request file.

The state root and configured host-key path must use canonical drive-letter Windows paths on fixed local volumes. UNC paths, device paths, alternate data streams, relative paths and reparse points are refused. These checks also apply to dynamically discovered installation and authority files.

The returned plan binds its request and observed dependencies to a SHA-256 digest. Review the complete plan: installed receipt and runtime, physical file identities and permissions, account identities and group membership, current configuration bytes, exact proposed bytes and permissions, configured host public keys, effective selected-account and control-account policies, and service and firewall facts. A digest identifies this proposal; it does not reserve the host or prevent another process from changing it.

The native reader derives public keys from the configured private host-key files through the pinned installed `ssh-keygen`. The command receives only public output. This proves which public key corresponds to the configured key file. It does not prove which key an already running SSH listener serves.

The current configuration's effective policy comes from the installed `sshd`. The proposed policy is an in-memory prediction. Apply must validate the actual staged configuration with the native parser before activation and reread the preview's dependencies before making changes.

## Supported configuration

This preview requires an already installed OpenSSH Server with file version `9.5.*`, one explicit Ed25519 host key and matching public companion file, a running automatic `sshd` service, exact existing listener and firewall scope, and a configuration within its supported grammar. A selected administrator also requires an independent administrator control account. Existing `Include` and `Match` directives refuse preview, including the Windows default administrator `Match` block. Do not remove existing policy to make a preview pass. Support for that default block remains required before the complete Windows pairing workflow is accepted.

Unknown configuration, destinations, account identity, installation ownership, executable provenance, permissions, or policy refuse preview. Preserve the returned problems and investigate the exact failed dependency. The preview does not repair or adopt existing files.

## Apply and pairing

SSH apply, operation observation and exact stop, host offer creation, enrollment and revocation remain separate implementation steps. Installation authority and a completed installation receipt do not authorize SSH changes. The preview cannot substitute for an enrollment receipt or a successful readiness check.

Local fixture proof covers the planner and command boundary. The CLI success fixture substitutes the private reader and owner construction; public refusal cases run against the unmodified binary. Windows cross-compilation checks compilation only. Native handle sharing, physical-volume paths, installed-tool compatibility and protected hosted pair-and-run remain required acceptance evidence.
