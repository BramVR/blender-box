#!/usr/bin/env python3
"""Trusted hosted client for the fixed persistent controller commands."""

import argparse
import base64
import binascii
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
    model.require(grant.get("candidate_sha") == env["CANDIDATE_SHA"] and grant.get("scope") == "host-install-pair-run-remove"
                  and grant.get("launch") is True and operator.get("fixture", {}).get("kind") == "dedicated"
                  and operator.get("fixture", {}).get("state") == "absent", "installer-not-authorized")
    now = datetime.now(timezone.utc)
    # A job that only recovers and collects rebuilds the starting job's exact request, so collect binds its digest.
    expires = env.get("REQUEST_EXPIRES_AT") or (now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Retained requests may expire while an observer waits for approval; the controller fences new launches.
    model.require(model.utc(expires) <= now + timedelta(hours=2), "hosted-authorization-invalid")
    request = model.ProofExecutionRequest.parse({"schema_version": 1, "repository": "BramVR/blender-box",
        "candidate_sha": env["CANDIDATE_SHA"], "driver_sha": env["DRIVER_SHA"], "variant": "host-install",
        "execution_id": env["PROOF_EXECUTION_ID"], "expires_at": expires})
    connection = model.document(env["INSTALL_CONTROLLER_CONFIG"].encode())
    model.require(set(connection) == {"schema_version", "hostname", "user", "port"}
                  and type(connection["port"]) is int, "controller-connection-invalid")
    raw = (f'Host proof-controller\nHostName {connection["hostname"]}\nUser {connection["user"]}\n'
           f'Port {connection["port"]}\nIdentityFile "{root / "key"}"\nUserKnownHostsFile "{root / "known_hosts"}"\n').encode()
    selected = model.ssh_connection(raw, "proof-controller")
    secrets = {"key": env["INSTALL_CONTROLLER_KEY"].encode(), "known_hosts": env["INSTALL_CONTROLLER_KNOWN_HOSTS"].encode()}
    model.require(all(0 < len(value) <= 64 << 10 and b"\x00" not in value for value in secrets.values()),
                  "controller-credentials-invalid")
    if not secrets["key"].endswith(b"\n"):
        secrets["key"] += b"\n"
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
    return request


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


def collect(root, *, commands=None):
    request = model.parse_command(model.read_private(root / "request.json", model.MAX_WIRE)).request
    model.require(request is not None and request.variant == "host-install", "invalid-command")
    if commands is None:
        attempt = root / "private" / "collect"
        model.private_directory(attempt, create=True)
        commands = proof.Commands(attempt, root)
    command = proof.canonical({"schema_version": 1, "operation": "collect", "execution_id": request.execution_id})
    raw = commands.run(["ssh", "-F", root / "ssh-config", "-T", "--", "proof-controller", "dispatch"],
                       stdin=command, timeout=300, limit=model.MAX_COLLECT_RESPONSE)
    value = model.document(raw, model.MAX_COLLECT_RESPONSE)
    model.require(set(value) == {"schema_version", "operation", "execution_id", "files"}
                  and value["operation"] == "collect" and value["execution_id"] == request.execution_id
                  and isinstance(value["files"], list) and 1 <= len(value["files"]) <= 2, "collect-response-invalid")
    files = {}
    for item in value["files"]:
        model.require(isinstance(item, dict) and set(item) == {"name", "size", "sha256", "content_base64"}
                      and item["name"] in ("outcome.json", "viewport.png") and item["name"] not in files
                      and isinstance(item["content_base64"], str), "collect-response-invalid")
        try:
            content = base64.b64decode(item["content_base64"], validate=True)
        except (binascii.Error, ValueError) as error:
            raise model.ControllerError("collect-response-invalid") from error
        model.require(len(content) == item["size"] and proof.digest(content) == item["sha256"], "collect-response-invalid")
        files[item["name"]] = content
    model.require("outcome.json" in files, "collect-response-invalid")
    envelope = model.document(files["outcome.json"], model.MAX_FILE, version=2)
    model.require(set(envelope) == {"schema_version", "kind", "request", "baseline", "settlement"}
                  and envelope["kind"] == "baseline-collect"
                  and envelope["request"] == {"execution_id": request.execution_id, "request_sha256": request.digest,
                                              "candidate_sha": request.candidate_sha, "driver_sha": request.driver_sha,
                                              "variant": request.variant}, "collect-outcome-invalid")
    baseline, settlement = envelope["baseline"], envelope["settlement"]
    model.require(isinstance(baseline, dict) and set(baseline) == {"record_sha256", "report"}
                  and isinstance(settlement, dict) and set(settlement) == {"receipt", "recovery"}
                  and isinstance(baseline["report"], dict) and "installation_settlement" not in baseline["report"],
                  "collect-outcome-invalid")
    settled = receipt(proof.canonical(settlement["receipt"]), request.execution_id)
    # Exact key sets keep unexpected private fields out of the public artifact. The controller binds the
    # client hash to its enrolled policy; this runner has no independent copy of that pin.
    binaries = baseline["report"].get("binaries")
    report = model.baseline_report(baseline["report"], request,
                                   binaries.get("client_sha256") if isinstance(binaries, dict) else None)
    outcomes = report["outcomes"]
    viewport = [item for item in report["artifacts"] if item.get("type") == "viewport"]
    if "viewport.png" in files:
        model.require(len(viewport) == 1 and len(files["viewport.png"]) == viewport[0]["size"]
                      and proof.digest(files["viewport.png"]) == viewport[0]["local_sha256"], "collect-viewport-invalid")
        proof.verify_png(files["viewport.png"], viewport[0]["width"], viewport[0]["height"])
        model.publish(root / "public/viewport.png", files["viewport.png"], exclusive=False)
    model.publish(root / "public/outcome.json", files["outcome.json"], exclusive=False)
    return (report["status"] == "pass" and all(item["status"] == "pass" for item in outcomes.values())
            and settled["phase"] == "settled" and settled["proof_result"] == "pass"
            and report["run"] is not None and report["run"].get("session_id") is not None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "start", "status", "recover", "collect"))
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.operation == "prepare":
            print("expires_at=" + prepare(args.directory.absolute(), os.environ).expires_at)
            return 0
        if args.operation == "collect":
            return 0 if collect(args.directory.absolute()) else 1
        result = dispatch(args.directory.absolute(), args.operation)
        return 0 if result["phase"] == "settled" and result["proof_result"] == "pass" else 1
    except (OSError, KeyError, TypeError, AttributeError, ValueError, model.ControllerError, proof.ProofError):
        print("Persistent controller proof remains unconfirmed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
