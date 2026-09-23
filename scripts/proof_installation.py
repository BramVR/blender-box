"""Retained authority for one separately granted host installation."""

from dataclasses import asdict
import copy
import json
import uuid
from pathlib import Path

import proof_controller as model

proof = model.proof
MAX_CHECKPOINT = 128 << 10
MAX_REVISIONS = 128
STAGES = {"bound", "install-released", "install-observed", "installed", "target-bound", "run-released",
          "run-owned", "run-clean", "remove-released", "remove-observed", "removed"}


def exact(value, fields):
    model.require(isinstance(value, dict) and set(value) == set(fields), "installation-record-invalid")


def retain_inputs(control, job, policy, files):
    original = files.read(policy.operator_config, 64 << 10)
    value = model.document(original)
    raw_manifest = files.read(Path(value["runtime"]["local_manifest"]), 128 << 10)
    operator = proof.InstallOperator.from_document(value, job.request.candidate_sha, raw_manifest)
    model.require(raw_manifest == operator.raw_manifest and operator.ssh_config is not None,
                  "original-inputs-unavailable")
    source = files.read(operator.ssh_config, 64 << 10)
    connection = model.ssh_connection(source, operator.connection["ssh_alias"])
    value["ssh_config"] = str(job.root / "inputs/ssh-config")
    value["runtime"]["local_manifest"] = str(job.root / "inputs/runtime-manifest.json")
    contents = {"original-operator.json": original, "original-ssh-config": source,
                "operator.json": proof.canonical(value), "runtime-manifest.json": raw_manifest,
                "ssh-config": model.normalized_ssh(connection, job.root / "inputs"),
                "key": files.read(Path(connection["identityfile"]), 64 << 10),
                "known_hosts": files.read(Path(connection["userknownhostsfile"]), 64 << 10)}
    manifest = {"schema_version": 2, "variant": "host-install", "files": {
        name: proof.digest(content) for name, content in contents.items()},
        "candidate_checkout": str(job.candidate_checkout), "config": str(job.config),
        "expected_client_sha256": job.expected_client_sha256}
    for root in (control, job.root):
        files.directory(root / "inputs", create=True)
        for name, content in contents.items():
            files.publish(root / "inputs" / name, content)
        files.publish(root / "inputs.json", proof.canonical(manifest))
    return proof.digest(proof.canonical(manifest))


def create_anchor(control, job, files):
    operator = retained_operator(job, files, control=control)
    anchor = {"schema_version": 2, "variant": "host-install", "request_digest": job.request.digest,
              "inputs_digest": job.inputs_digest, "installation_id": operator.installation["id"],
              "grant_sha256": proof.digest(proof.canonical(operator.authorization)),
              "operations": {name: "bbxo_" + uuid.uuid4().hex for name in ("install", "remove")}}
    initial = {"schema_version": 2, "anchor_sha256": proof.digest(proof.canonical(anchor)), "sequence": 0,
               "previous": proof.digest(proof.canonical(anchor)), "stage": "bound", "data": {}}
    files.publish(control / "installation-0000.json", proof.canonical(initial))
    return anchor


def validate_anchor(anchor, job):
    exact(anchor, ("schema_version", "variant", "request_digest", "inputs_digest", "installation_id",
                   "grant_sha256", "operations"))
    model.require(type(anchor["schema_version"]) is int and anchor["schema_version"] == 2
                  and anchor["variant"] == job.request.variant == "host-install"
                  and anchor["request_digest"] == job.request.digest and anchor["inputs_digest"] == job.inputs_digest
                  and proof.matches(r"bbxi_[a-f0-9]{32}", anchor["installation_id"])
                  and proof.matches(proof.HASH, anchor["grant_sha256"]), "installation-anchor-invalid")
    exact(anchor["operations"], ("install", "remove"))
    model.require(all(proof.matches(r"bbxo_[a-f0-9]{32}", item) for item in anchor["operations"].values())
                  and len(set(anchor["operations"].values())) == 2, "installation-anchor-invalid")


def execution_pin(result):
    execution = proof.validate_installer_execution(result)
    return {key: execution[key] for key in ("token", "request_sha256", "deadline", "process_state", "keeper", "worker")
            if key in execution}


def same_execution(before, after):
    proof.require_same_installer_execution(execution_pin(before), execution_pin(after))


def intent(operator, anchor, operation, preview):
    return {"operation": operation, "operation_id": anchor["operations"][operation],
            "installation_id": anchor["installation_id"], "preview": preview,
            "target_out": operator.installation["target_out"] if operation == "install" else ""}


def validate_intent(value, anchor, operator, operation):
    exact(value, ("operation", "operation_id", "installation_id", "preview", "target_out"))
    model.require(value["operation"] == operation and value["operation_id"] == anchor["operations"][operation]
                  and value["installation_id"] == anchor["installation_id"]
                  and value["target_out"] == (operator.installation["target_out"] if operation == "install" else ""),
                  "installation-intent-changed")
    preview = value["preview"]
    proof.validate_installer_result(preview, operator, operation, operation_id=value["operation_id"],
                                   target_out=operation == "install")
    model.require(type(preview.get("schema_version")) is int and preview["schema_version"] == 1
                  and preview["state"] == ("planned" if operation == "install" else "installed")
                  and preview["plan"].get("state_root") == operator.installation["state_root"]
                  and preview["plan"].get("windows_user") == operator.connection["windows_user"]
                  and "task" in preview["plan"], "installation-intent-changed")


def validate_observation(value, selected, operator, *, terminal=None):
    proof.validate_installer_result(value, operator, "status", operation_id=selected["operation_id"],
                                   expected_plan=selected["preview"]["plan"]["plan_sha256"], target_out=bool(selected["target_out"]))
    model.require(isinstance(value, dict) and type(value.get("schema_version")) is int and value["schema_version"] == 1
                  and value.get("installation_id") == selected["installation_id"]
                  and value.get("operation_id") == selected["operation_id"]
                  and value.get("plan") == selected["preview"]["plan"] and value.get("inspection") == selected["preview"]["inspection"],
                  "installation-observation-changed")
    publication = value.get("target_publication", {})
    model.require(isinstance(publication, dict) and (publication.get("path") == selected["target_out"]
                  and publication.get("status") in ("published", "failed", "not-published") if selected["target_out"]
                  else publication == {"status": "not-requested"}), "installation-observation-changed")
    proof.validate_installer_execution(value, terminal=terminal is not None)
    if terminal is not None:
        model.require(value.get("state") == terminal, "installation-unsettled")


def target_fingerprint(raw):
    target = proof.windows_target(model.document(raw, version=2))
    fields = ("ssh_user", "interactive_user", "work_root", "task_name", "blender_executable",
              "session_broker_executable", "host_executable")
    normalized = {"schema_version": 2, "platform": "windows", "ssh_alias": target["ssh_alias"],
                  "windows": {key: target[key] for key in fields}}
    encoded = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False)
    for character in ("&", "<", ">", "\u2028", "\u2029"):
        encoded = encoded.replace(character, "\\u" + format(ord(character), "04x"))
    return proof.digest(b"blender-box-target-v1\x00" + encoded.encode())


def validate_run(run):
    exact(run, ("run_id", "marker_sha256", "journal_sha256", "journal", "session"))
    model.require(proof.matches(proof.RUN_ID, run["run_id"])
                  and all(proof.matches(proof.HASH, run[key]) for key in ("marker_sha256", "journal_sha256")),
                  "original-run-unavailable")
    journal = run["journal"]
    exact(journal, ("schema_version", "claim", "target_fingerprint"))
    claim = journal["claim"]
    exact(claim, ("schema_version", "run_id", "request_id", "controller_id", "deadline", "request_hash", "task_name"))
    proof.Fence.parse(claim, require_session=False)
    model.require(journal["schema_version"] == 1 and claim["run_id"] == run["run_id"]
                  and proof.matches(proof.HASH, journal["target_fingerprint"])
                  and all(isinstance(claim[key], str) and claim[key].strip() and len(claim[key]) <= 256
                          for key in ("controller_id", "task_name")), "original-run-unavailable")
    if run["session"] != {}:
        exact(run["session"], ("sha256", "record"))
        pin = run["session"]["record"]
        exact(pin, ("schema_version", "run_id", "claim", "target_fingerprint", "session_id"))
        model.require(pin["schema_version"] == 1 and pin["run_id"] == run["run_id"] and pin["claim"] == claim
                      and pin["target_fingerprint"] == journal["target_fingerprint"]
                      and proof.matches(proof.HASH, run["session"]["sha256"])
                      and proof.matches(r"bss_[A-Za-z0-9_-]{16,128}", pin["session_id"]), "original-run-unavailable")


def parse_stage(stage, data, anchor, operator):
    model.require(stage in STAGES, "installation-stage-invalid")
    if stage == "bound":
        exact(data, ())
    elif stage in ("install-released", "install-observed", "installed"):
        exact(data, ("intent",) if stage == "install-released" else ("intent", "observed"))
        validate_intent(data["intent"], anchor, operator, "install")
        if stage != "install-released":
            validate_observation(data["observed"], data["intent"], operator, terminal="installed" if stage == "installed" else None)
    elif stage == "target-bound":
        exact(data, ("install", "target_sha256"))
        parse_stage("installed", data["install"], anchor, operator)
        model.require(proof.matches(proof.HASH, data["target_sha256"]), "installation-target-invalid")
    elif stage in ("run-released", "run-owned", "run-clean"):
        exact(data, {"target"} | ({"run"} if stage != "run-released" else set())
              | ({"cleanup", "install_repeat"} if stage == "run-clean" else set()))
        parse_stage("target-bound", data["target"], anchor, operator)
        if stage != "run-released":
            validate_run(data["run"])
        if stage == "run-clean":
            proof.verify_cleanup({"cleanup": data["cleanup"]})
            model.require(data["install_repeat"] in ("pending", "released", "verified"), "installation-repeat-invalid")
    else:
        exact(data, {"prior", "intent"} | ({"observed"} if stage != "remove-released" else set())
              | ({"preserved", "remove_repeat"} if stage == "removed" else set()))
        prior = data["prior"]
        exact(prior, ("stage", "data"))
        model.require(prior["stage"] in ("installed", "target-bound", "run-clean"), "installation-run-unsettled")
        parse_stage(prior["stage"], prior["data"], anchor, operator)
        model.require(prior["stage"] != "run-clean" or prior["data"]["install_repeat"] != "released",
                      "installation-repeat-unsettled")
        validate_intent(data["intent"], anchor, operator, "remove")
        if stage != "remove-released":
            validate_observation(data["observed"], data["intent"], operator, terminal="removed" if stage == "removed" else None)
        if stage == "removed":
            model.require(data["remove_repeat"] in ("pending", "released", "verified"), "installation-repeat-invalid")
            observation = data["preserved"]
            original = prior["data"] if prior["stage"] == "installed" else (
                prior["data"]["install"] if prior["stage"] == "target-bound" else prior["data"]["target"]["install"])
            if original["observed"]["target_publication"]["status"] == "published":
                model.require(observation.get("target_absent") is False, "installation-target-missing")
            exact(observation, operator.before)
            model.require(observation["installation_absent"] is False and observation["task_absent"] is True
                          and type(observation["target_absent"]) is bool
                          and all(observation[key] == operator.before[key] for key in ("unrelated_files", "unrelated_tasks")),
                          "installation-removal-unproven")


def accept_transition(before, after, anchor, operator, invocation):
    exact(after, ("schema_version", "anchor_sha256", "sequence", "previous", "invocation", "stage", "data"))
    model.require(type(after["schema_version"]) is int and after["schema_version"] == 2
                  and after["anchor_sha256"] == before["anchor_sha256"] == proof.digest(proof.canonical(anchor))
                  and type(after["sequence"]) is int and after["sequence"] == before["sequence"] + 1 < MAX_REVISIONS
                  and after["previous"] == proof.digest(proof.canonical(before))
                  and after["invocation"] == asdict(invocation)
                  and invocation.request_digest == anchor["request_digest"], "installation-checkpoint-stale")
    parse_stage(after["stage"], after["data"], anchor, operator)
    old, new, left, right = before["stage"], after["stage"], before["data"], after["data"]
    allowed = {"bound": {"install-released"}, "install-released": {"install-observed"},
               "install-observed": {"install-observed", "installed"}, "installed": {"target-bound", "remove-released"},
               "target-bound": {"run-released", "remove-released"}, "run-released": {"run-owned"},
               "run-owned": {"run-owned", "run-clean"}, "run-clean": {"run-clean", "remove-released"},
               "remove-released": {"remove-observed"}, "remove-observed": {"remove-observed", "removed"}, "removed": {"removed"}}
    model.require(new in allowed[old], "installation-transition-invalid")
    if new == "remove-released":
        model.require(right["prior"] == {"stage": old, "data": left}, "installation-authority-changed")
    elif new == "target-bound":
        model.require(right["install"] == left, "installation-authority-changed")
    elif new == "run-released":
        model.require(right["target"] == left, "installation-authority-changed")
    elif old != "bound":
        for key, value in left.items():
            if key in ("install_repeat", "remove_repeat"):
                model.require((value, right[key]) in (("pending", "released"), ("released", "verified")),
                              "installation-repeat-invalid")
            elif key == "observed":
                same_execution(value, right[key])
            elif key == "run":
                model.require({k: v for k, v in value.items() if k != "session"}
                              == {k: v for k, v in right[key].items() if k != "session"}
                              and (not value["session"] or value["session"] == right[key]["session"]),
                              "original-run-changed")
            else:
                model.require(right[key] == value, "installation-authority-changed")
    model.require(old != new or left != right, "installation-checkpoint-duplicate")
    model.require(len(proof.canonical(after)) <= MAX_CHECKPOINT, "installation-checkpoint-limit")
    return after


def retained_operator(job, files, *, control=None):
    root = control or job.root
    manifest_raw = files.read(root / "inputs.json")
    model.require(proof.digest(manifest_raw) == job.inputs_digest, "original-inputs-unavailable")
    manifest = model.document(manifest_raw, version=2)
    operator_raw = files.read(root / "inputs/operator.json", 64 << 10)
    runtime = files.read(root / "inputs/runtime-manifest.json", 128 << 10)
    model.require(proof.digest(operator_raw) == manifest["files"]["operator.json"]
                  and proof.digest(runtime) == manifest["files"]["runtime-manifest.json"], "original-inputs-unavailable")
    return proof.InstallOperator.from_document(model.document(operator_raw), job.request.candidate_sha, runtime)


def read_chain(control, job, anchor, files):
    validate_anchor(anchor, job)
    operator = retained_operator(job, files, control=control)
    model.require(anchor["installation_id"] == operator.installation["id"]
                  and anchor["grant_sha256"] == proof.digest(proof.canonical(operator.authorization)),
                  "installation-anchor-invalid")
    names = sorted(path.name for path in files.entries(control) if path.name.startswith("installation-"))
    model.require(0 < len(names) <= MAX_REVISIONS and names == [f"installation-{i:04d}.json" for i in range(len(names))],
                  "installation-chain-invalid")
    previous = None
    for index, name in enumerate(names):
        record = model.document(files.read(control / name, MAX_CHECKPOINT), MAX_CHECKPOINT, version=2)
        if index == 0:
            expected = {"schema_version": 2, "anchor_sha256": proof.digest(proof.canonical(anchor)), "sequence": 0,
                        "previous": proof.digest(proof.canonical(anchor)), "stage": "bound", "data": {}}
            model.require(record == expected, "installation-chain-invalid")
        else:
            inv = model.Invocation.parse(record.get("invocation"))
            model.require(inv.execution_id == job.request.execution_id and inv.attempt <= job.attempt,
                          "installation-chain-invalid")
            authorization = model.document(files.read(control / f"authorization-{inv.attempt:04d}.json"))
            model.require(authorization.get("invocation") == asdict(inv)
                          and (previous["sequence"] == 0 or inv.attempt >= previous["invocation"]["attempt"]),
                          "installation-chain-invalid")
            accept_transition(previous, record, anchor, operator, inv)
        previous = record
    return previous


def read_run(job, files):
    marker_raw = files.read(job.output / "private/run-journal.json", 4096)
    marker = model.document(marker_raw, 4096)
    exact(marker, ("schema_version", "run_id"))
    model.require(marker["schema_version"] == 1 and proof.matches(proof.RUN_ID, marker["run_id"]), "original-run-unavailable")
    journal_path = job.config / "runs" / (marker["run_id"] + ".json")
    raw = files.read(journal_path, 16 << 10)
    session_path = journal_path.with_suffix(".session.json")
    session = {}
    if files.exists(session_path):
        pin = files.read(session_path, 16 << 10)
        session = {"sha256": proof.digest(pin), "record": model.document(pin)}
    result = {"run_id": marker["run_id"], "marker_sha256": proof.digest(marker_raw),
              "journal_sha256": proof.digest(raw), "journal": model.document(raw), "session": session}
    validate_run(result)
    return result


def protected_references(record, job, files, *, operator=None):
    stage, data = record["stage"], record["data"]
    if stage.startswith("remove"):
        stage, data = data["prior"]["stage"], data["prior"]["data"]
    if stage == "target-bound" or stage.startswith("run-"):
        target = data if stage == "target-bound" else data["target"]
        raw = files.read(job.output / "private/target.json", 64 << 10)
        model.require(proof.digest(raw) == target["target_sha256"]
                      and model.document(raw, version=2) == target["install"]["observed"].get("target"), "original-target-changed")
        actual = proof.windows_target(model.document(raw, version=2))
        operator = operator or retained_operator(job, files)
        runtime = proof.windows_path(operator.installation["state_root"]) / "installations" / operator.installation["id"] / "runtime"
        expected = dict(operator.windows, host_executable=str(runtime / "blender-box.exe"),
                        session_broker_executable=str(runtime / "blendersessiond.exe"))
        model.require(actual == expected, "original-target-changed")
        model.require(proof.digest(files.read(job.output / "private/blender-box", 128 << 20))
                      == job.expected_client_sha256, "client-artifact-mismatch")
    if stage in ("run-owned", "run-clean"):
        model.require(read_run(job, files) == data["run"]
                      and data["run"]["journal"]["target_fingerprint"] == target_fingerprint(raw)
                      and data["run"]["journal"]["claim"]["task_name"] == actual["task_name"], "original-run-changed")


def publish_checkpoint(control, job, anchor, invocation, proposal, files):
    model.require((invocation.execution_id, invocation.attempt, invocation.request_digest) ==
                  (job.request.execution_id, job.attempt, job.request.digest), "installation-checkpoint-stale")
    authorization = model.document(files.read(control / f"authorization-{job.attempt:04d}.json"))
    model.require(authorization == {"schema_version": 1, "invocation": asdict(invocation),
                  "mode": "baseline" if job.attempt == 1 else "recover"}, "installation-checkpoint-stale")
    model.verify_inputs(control, job, job.inputs_digest, files)
    latest = read_chain(control, job, anchor, files)
    accepted = accept_transition(latest, proposal, anchor, retained_operator(job, files, control=control), invocation)
    protected_references(accepted, job, files, operator=retained_operator(job, files, control=control))
    raw = proof.canonical(accepted)
    files.publish(control / f"installation-{accepted['sequence']:04d}.json", raw)
    return {"schema_version": 2, "type": "checkpoint-ack", "invocation": asdict(invocation),
            "sequence": accepted["sequence"], "sha256": proof.digest(raw)}


class Checkpoints:
    def __init__(self, job, anchor, latest, invocation, exchange):
        validate_anchor(anchor, job)
        self.job, self.anchor, self.latest, self.invocation, self.exchange = job, anchor, latest, invocation, exchange
        self.broken = False

    def advance(self, stage, data):
        model.require(not self.broken, "installation-ack-unavailable")
        proposal = {"schema_version": 2, "anchor_sha256": proof.digest(proof.canonical(self.anchor)),
                    "sequence": self.latest["sequence"] + 1, "previous": proof.digest(proof.canonical(self.latest)),
                    "invocation": asdict(self.invocation), "stage": stage, "data": copy.deepcopy(data)}
        try:
            ack = self.exchange({"schema_version": 2, "type": "checkpoint", "record": proposal})
            model.require(ack == {"schema_version": 2, "type": "checkpoint-ack", "invocation": asdict(self.invocation),
                          "sequence": proposal["sequence"], "sha256": proof.digest(proof.canonical(proposal))},
                          "installation-ack-invalid")
        except BaseException:
            self.broken = True
            raise
        self.latest = proposal
        return proposal


def settlement(latest, result, operator):
    value = result.get("installation_settlement")
    exact(value, ("stage", "chain_sha256", "observation"))
    model.require(value["stage"] == latest["stage"] and value["chain_sha256"] == proof.digest(proof.canonical(latest)),
                  "installation-settlement-changed")
    if latest["stage"] == "bound":
        model.require(value["observation"] == operator.before, "installation-untouched-unproven")
    else:
        model.require(latest["stage"] == "removed" and latest["data"]["remove_repeat"] != "released"
                      and value["observation"] == latest["data"]["preserved"],
                      "installation-removal-unproven")
    return True


class Installation:
    def __init__(self, checkpoints, commands, operator):
        self.checkpoints, self.commands, self.operator = checkpoints, commands, operator
        self.job = checkpoints.job
        self.files = model.local_files()

    @property
    def stage(self):
        return self.checkpoints.latest["stage"]

    @property
    def data(self):
        return self.checkpoints.latest["data"]

    def advance(self, stage, data):
        model.require(self.commands.group_cleanup_known, "command-cleanup-unknown")
        return self.checkpoints.advance(stage, data)

    def observe_execution(self, operation, result):
        observed_stage = operation + "-observed"
        model.require(self.stage in (operation + "-released", observed_stage), "installation-transition-invalid")
        validate_observation(result, self.data["intent"], self.operator)
        if self.stage == observed_stage:
            same_execution(self.data["observed"], result)
            if self.data["observed"] == result:
                return
        self.advance(observed_stage, {**self.data, "observed": result})

    def settle_operation(self, operation):
        selected = self.data["intent"]
        result = proof.recover_installer(self.commands, self.operator, selected["operation_id"],
            selected["preview"]["plan"]["plan_sha256"], target_out=operation == "install",
            checkpoint=lambda observed: self.observe_execution(operation, observed))
        validate_observation(result, selected, self.operator, terminal="installed" if operation == "install" else "removed")
        if operation == "install":
            self.advance("installed", {"intent": selected, "observed": result})
        return result

    def install(self, report):
        model.require(self.stage == "bound", "installation-already-released")
        ids = self.checkpoints.anchor["operations"]
        model.publish(self.commands.private / "installer-operations.json", proof.canonical({
            "schema_version": 1, "installation_id": self.operator.installation["id"], "operations": ids}))
        observation = proof.installer_observation(self.commands, self.operator)
        model.require(observation == self.operator.before, "installer-before-state-changed")
        inspected = proof.installer_call(self.commands, self.operator, "inspect", fresh=True)
        model.require(inspected["state"] == "planned", "installer-inspect-mismatch")
        report["outcomes"]["install-inspect"] = {"status": "pass", "code": "dedicated-absent-fixture-verified"}
        preview = proof.installer_call(self.commands, self.operator, "install", operation_id=ids["install"], target_out=True)
        model.require(preview["state"] == "planned"
                      and proof.installer_observation(self.commands, self.operator) == observation, "installer-preview-mutated")
        report["outcomes"]["install-preview"] = {"status": "pass", "code": "install-preview-read-only"}
        selected = intent(self.operator, self.checkpoints.anchor, "install", preview)
        self.advance("install-released", {"intent": selected})
        applied = proof.installer_call(self.commands, self.operator, "install", operation_id=ids["install"],
            apply=True, expected_plan=selected["preview"]["plan"]["plan_sha256"], target_out=True)
        self.observe_execution("install", applied)
        observed = self.settle_operation("install")
        model.require(applied.get("target") == observed.get("target"), "installer-target-changed")
        report["installation"] = {"installation_id": self.operator.installation["id"], "state": "installed"}
        report["outcomes"]["install-apply"] = {"status": "pass", "code": "owned-runtime-installed"}
        return observed

    def bind_target(self, result, target_path):
        model.require(self.stage == "installed" and result == self.data["observed"], "installation-authority-changed")
        model.require(result["target_publication"]["status"] == "published", "installer-target-publication-failed")
        model.require(target_path == self.job.output / "private/target.json", "original-target-changed")
        actual = proof.installer_target(self.commands, self.operator, result, target_path)
        raw = self.files.read(target_path, 64 << 10)
        client_path = self.job.output / "private/blender-box"
        client = self.files.read(client_path, 128 << 20)
        model.require(proof.digest(client) == self.job.expected_client_sha256, "client-artifact-mismatch")
        model.publish(target_path, raw, exclusive=False)
        model.publish(client_path, client, exclusive=False, mode=0o700)
        self.advance("target-bound", {"install": self.data, "target_sha256": proof.digest(raw)})
        return actual

    def release_run(self):
        model.require(self.stage == "target-bound", "installation-run-unsettled")
        self.advance("run-released", {"target": self.data})

    def own_run(self):
        model.require(not self.checkpoints.broken, "installation-ack-unavailable")
        model.require(self.stage in ("run-released", "run-owned", "run-clean"), "installation-run-unsettled")
        model.sync_directory(self.job.output / "private")
        run = read_run(self.job, self.files)
        if self.stage == "run-clean":
            model.require(run == self.data["run"], "original-run-changed")
        elif self.stage == "run-released" or run != self.data["run"]:
            self.advance("run-owned", {"target": self.data["target"], "run": run})
        protected_references(self.checkpoints.latest, self.job, self.files)
        return run

    def cleanup_run(self, original_result=None):
        original = self.own_run()
        records = []
        for operation in ("status", "stop", "status"):
            self.own_run()
            record = self.commands.json([self.job.output / "private/blender-box", operation, "--target",
                self.job.output / "private/target.json", "--run", original["run_id"], "--timeout", "60s", "--json"],
                timeout=100, recovery=True)
            pinned = self.own_run()
            expected = {**original["journal"]["claim"], "session_id": pinned["session"].get("record", {}).get("session_id")}
            model.require(proof.Fence.parse(record, require_session=False) == proof.Fence.parse(expected, require_session=False),
                          "original-run-changed")
            records.append(record)
        expected = {**original["journal"]["claim"], "session_id": self.data["run"]["session"].get("record", {}).get("session_id")}
        cleanup = proof.verify_recovery(original_result or expected, *records)
        if self.stage == "run-owned":
            self.advance("run-clean", {**self.data, "cleanup": cleanup, "install_repeat": "pending"})
        return cleanup

    def remove(self):
        model.require(self.stage in ("installed", "target-bound", "run-clean"), "installation-run-unsettled")
        ids = self.checkpoints.anchor["operations"]
        preview = proof.installer_call(self.commands, self.operator, "remove", operation_id=ids["remove"], recovery=True)
        model.require(preview["state"] == "installed", "installer-remove-preview-mismatch")
        inspection = proof.installer_call(self.commands, self.operator, "inspect", recovery=True)
        model.require(inspection["state"] == "installed", "installer-remove-preview-mutated")
        prior = {"stage": self.stage, "data": self.data}
        selected = intent(self.operator, self.checkpoints.anchor, "remove", preview)
        self.advance("remove-released", {"prior": prior, "intent": selected})
        try:
            result = proof.installer_call(self.commands, self.operator, "remove", operation_id=ids["remove"], apply=True,
                expected_plan=selected["preview"]["plan"]["plan_sha256"], recovery=True)
        except Exception as error:
            # The root release remains authoritative when the apply reply is lost.
            result, failure = None, error
        else:
            failure = None
        if result is not None:
            self.observe_execution("remove", result)
        self.finish_removal()
        if failure is not None:
            raise failure

    def finish_removal(self):
        result = self.settle_operation("remove")
        observation = proof.installer_observation(self.commands, self.operator, recovery=True)
        data = {**self.data, "observed": result, "preserved": observation, "remove_repeat": "pending"}
        parse_stage("removed", data, self.checkpoints.anchor, self.operator)
        self.advance("removed", data)

    def repeat(self, operation, *, send=True):
        stage = "run-clean" if operation == "install" else "removed"
        key = operation + "_repeat"
        model.require(self.stage == stage, "installation-repeat-invalid")
        installed = self.data["target"]["install"] if operation == "install" else self.data
        selected, original = installed["intent"], installed["observed"]
        if send:
            model.require(self.data[key] == "pending", "installation-repeat-invalid")
            self.advance(stage, {**self.data, key: "released"})
            result = proof.installer_call(self.commands, self.operator, operation, operation_id=selected["operation_id"],
                apply=True, expected_plan=selected["preview"]["plan"]["plan_sha256"], target_out=operation == "install", recovery=True)
            validate_observation(result, selected, self.operator, terminal="installed" if operation == "install" else "removed")
            same_execution(original, result)
        else:
            model.require(self.data[key] == "released", "installation-repeat-invalid")
        # A repeated successful operation cannot authorize a new physical execution.
        result = proof.installer_call(self.commands, self.operator, "status", operation_id=selected["operation_id"],
            expected_plan=selected["preview"]["plan"]["plan_sha256"], target_out=operation == "install", recovery=True)
        validate_observation(result, selected, self.operator, terminal="installed" if operation == "install" else "removed")
        same_execution(original, result)
        model.require(result.get("target") == original.get("target") and result.get("files") == original.get("files"),
                      "installation-repeat-changed")
        self.advance(stage, {**self.data, key: "verified"})

    def recover(self):
        model.require(not self.checkpoints.broken and self.commands.group_cleanup_known, "installation-ack-unavailable")
        model.verify_worker_inputs(self.job)
        if self.stage == "bound":
            observation = proof.installer_observation(self.commands, self.operator, recovery=True)
            model.require(observation == self.operator.before, "installation-untouched-unproven")
            return self.result(observation)
        if self.stage in ("install-released", "install-observed"):
            self.settle_operation("install")
        if self.stage in ("run-released", "run-owned", "run-clean"):
            self.cleanup_run()
        if self.stage == "run-clean" and self.data["install_repeat"] == "released":
            self.repeat("install", send=False)
        if self.stage in ("installed", "target-bound", "run-clean"):
            self.remove()
        elif self.stage in ("remove-released", "remove-observed"):
            self.finish_removal()
        model.require(self.stage == "removed", "installation-removal-unproven")
        if self.data["remove_repeat"] == "released":
            self.repeat("remove", send=False)
        observation = proof.installer_observation(self.commands, self.operator, recovery=True)
        model.require(observation == self.data["preserved"], "installation-removal-changed")
        return self.result(observation)

    def result(self, observation):
        return {"installation_settlement": {"stage": self.stage,
                "chain_sha256": proof.digest(proof.canonical(self.checkpoints.latest)), "observation": observation}}


def prove(job, request, commands_factory, native_authority):
    checkpoints = getattr(native_authority, "checkpoints", None)
    model.require(isinstance(checkpoints, Checkpoints) and checkpoints.job == job, "installation-ack-unavailable")
    return proof.baseline(request, commands_factory, native_authority=native_authority, installation_checkpoints=checkpoints)


def recover(job, retained, checkpoints, commands_factory):
    model.require(checkpoints.anchor == retained["anchor"] and checkpoints.latest == retained["latest"],
                  "installation-authority-changed")
    model.verify_worker_inputs(job)
    model.private_directory(job.attempt_root / "commands", create=True)
    commands = commands_factory(job.attempt_root / "commands", job.candidate_checkout)
    commands.env["BLENDER_BOX_CONFIG_DIR"] = str(job.config)
    proof.configure_ssh(commands, job.root / "inputs/ssh-config")
    operator = retained_operator(job, model.local_files())
    return Installation(checkpoints, commands, operator).recover()
