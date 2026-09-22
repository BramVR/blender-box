#!/usr/bin/env python3
"""Trusted hosted client for the fixed persistent controller commands."""

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import time

import proof_controller as model

proof = model.proof


def prepare(root, env):
    model.require(env.get("GITHUB_RUN_ATTEMPT") == "1", "hosted-authorization-invalid")
    original = env["INSTALL_OPERATOR_CONFIG"].encode()
    model.require(0 < len(original) <= 64 << 10, "installer-config-invalid")
    operator = model.document(original)
    grant = operator.get("authorization", {})
    model.require(grant.get("candidate_sha") == env["CANDIDATE_SHA"] and grant.get("scope") == "host-install-run-remove"
                  and grant.get("launch") is True and operator.get("fixture", {}).get("kind") == "dedicated"
                  and operator.get("fixture", {}).get("state") == "absent", "installer-not-authorized")
    request = model.ProofExecutionRequest.parse({"schema_version": 1, "repository": "BramVR/blender-box",
        "candidate_sha": env["CANDIDATE_SHA"], "driver_sha": env["DRIVER_SHA"], "variant": "host-install",
        "execution_id": env["PROOF_EXECUTION_ID"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")})
    connection = model.document(env["INSTALL_CONTROLLER_CONFIG"].encode())
    model.require(set(connection) == {"schema_version", "hostname", "user", "port"}
                  and type(connection["port"]) is int, "controller-connection-invalid")
    raw = (f'Host proof-controller\nHostName {connection["hostname"]}\nUser {connection["user"]}\n'
           f'Port {connection["port"]}\nIdentityFile "{root / "key"}"\nUserKnownHostsFile "{root / "known_hosts"}"\n').encode()
    selected = model.ssh_connection(raw, "proof-controller")
    secrets = {"key": env["INSTALL_CONTROLLER_KEY"].encode(), "known_hosts": env["INSTALL_CONTROLLER_KNOWN_HOSTS"].encode()}
    model.require(all(0 < len(value) <= 64 << 10 and b"\x00" not in value for value in secrets.values()),
                  "controller-credentials-invalid")
    model.private_directory(root, create=True)
    for name in ("private", "public"):
        model.private_directory(root / name, create=True)
    for name, value in secrets.items():
        model.publish(root / name, value)
    model.publish(root / "operator.json", original)
    model.publish(root / "ssh-config", model.normalized_ssh(selected, root))
    command = {"schema_version": 1, "operation": "start", "request": asdict(request),
               "installer_operator_sha256": proof.digest(original)}
    model.parse_command(proof.canonical(command))
    model.publish(root / "request.json", proof.canonical(command))
    return request.execution_id


def receipt(raw, execution_id):
    value = model.document(raw, model.MAX_WIRE)
    model.require(set(value) == {"schema_version", *model.PUBLIC_FIELDS}
                  and value["execution_id"] == execution_id and value["phase"] in model.PHASES
                  and type(value["closed"]) is bool and type(value["attempt"]) is int and 0 <= value["attempt"] <= 9999
                  and value["local_termination"] in ("unknown", "proven")
                  and value["windows_cleanup"] in ("unknown", "proven")
                  and value["proof_result"] in ("not-run", "pass", "fail"), "controller-receipt-invalid")
    model.require(value["phase"] != "settled" or value["closed"] and value["local_termination"] == "proven"
                  and value["windows_cleanup"] == "proven" and value["proof_result"] != "not-run", "controller-receipt-invalid")
    return value


def dispatch(root, operation, *, commands=None, clock=time.monotonic, wait=time.sleep, budget=3600):
    original = model.read_private(root / "request.json", model.MAX_WIRE)
    request = model.parse_command(original).request
    model.require(request is not None and request.variant == "host-install" and operation in ("start", "status", "recover"),
                  "invalid-command")
    if commands is None:
        attempt = root / "private" / operation
        model.private_directory(attempt, create=True)
        commands = proof.Commands(attempt, root)
    deadline = clock() + budget
    command = original if operation == "start" else proof.canonical({"schema_version": 1, "operation": operation,
                                                                   "execution_id": request.execution_id})
    while True:
        model.require(clock() < deadline, "controller-observation-expired")
        raw = commands.run(["ssh", "-F", root / "ssh-config", "-T", "--", "proof-controller", "dispatch"],
                           stdin=command, timeout=min(60, deadline - clock()), limit=model.MAX_WIRE)
        observed = receipt(raw, request.execution_id)
        model.publish(root / "public/receipt.json", proof.canonical(observed), exclusive=False)
        if operation == "status" or observed["phase"] in ("settled", "unresolved"):
            return observed
        wait(min(15, max(0, deadline - clock())))
        command = proof.canonical({"schema_version": 1, "operation": "status", "execution_id": request.execution_id})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "start", "status", "recover"))
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.operation == "prepare":
            prepare(args.directory.absolute(), os.environ)
            return 0
        result = dispatch(args.directory.absolute(), args.operation)
        return 0 if result["phase"] == "settled" and result["proof_result"] == "pass" else 1
    except (OSError, KeyError, ValueError, model.ControllerError, proof.ProofError):
        print("Persistent controller proof remains unconfirmed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
