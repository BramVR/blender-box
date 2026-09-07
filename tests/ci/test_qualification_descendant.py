import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone


@unittest.skipUnless(os.name == "posix", "owned POSIX subprocess")
class DescendantHoldTests(unittest.TestCase):
    def test_worker_and_descendant_wait_for_owned_stop_instead_of_returning_pass(self):
        source = Path(__file__).resolve().parents[2] / "scripts"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            script = r'''
import json, os, sys, time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
import proof_controller_native as native
import proof_qualification_fixture as fixture
native.JOBS = Path(sys.argv[2])
identity = "q-" + "a" * 32
root = native.JOBS / "qualification" / identity
root.mkdir(parents=True, mode=0o700)
(root.parent).chmod(0o700)
fixture.ctypes.CDLL = lambda *a, **k: SimpleNamespace(prctl=lambda *a: 1)
fixture.os.getgroups = lambda: []
native.LinuxOps.process = lambda self, pid: native.Process(pid, os.getpid(), 1, native.UNIT_CGROUP + "/attempt-" + "b" * 32)
actual_select = fixture.select.select
def held(*args):
    action = json.loads((root / "action.json").read_bytes())
    print(json.dumps({"event": "held", "parent": os.getpid(), "descendant": action["observations"]["descendant"]["pid"]}), flush=True)
    return actual_select(*args)
fixture.select.select = held
intent = native.LinuxIntent.parse({"schema_version":1,"family":"linux-native-v1","qualification_id":identity,
    "policy_sha256":"c"*64,"installation_sha256":"d"*64,"deadline_unix":int(time.time())+60,
    "case":"descendant-stop","accepted_boot_id":"e"*32})
completed = fixture.run_fixture(intent)
print(json.dumps({"event":"returned", "result": completed}), flush=True)
'''
            command = [sys.executable, "-B", "-c", script, str(source), str(root)]
            started_at = datetime.now(timezone.utc).isoformat()
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            owner = {"pid": process.pid, "parent": os.getpid(), "command": command, "group": os.getpgid(process.pid),
                     "started_at": started_at, "task": "qualification-descendant-regression", "unreaped": True}
            self.assertEqual(owner["group"], process.pid)
            try:
                self.assertTrue(select.select([process.stdout], [], [], 10)[0], "fixture receipt deadline")
                raw = process.stdout.readline()
                self.assertTrue(raw, "fixture exited before receipt")
                receipt = json.loads(raw)
                self.assertEqual(receipt["event"], "held", receipt)
                self.assertEqual(receipt["parent"], process.pid)
                self.assertEqual(os.getpgid(receipt["descendant"]), owner["group"])
            finally:
                try:
                    os.killpg(owner["group"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
                process.stdout.close()
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
