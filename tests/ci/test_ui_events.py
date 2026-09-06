"""Execute the embedded UI backend with deterministic Blender and Win32 boundaries."""
import ctypes
import json
import os
import tempfile
from pathlib import Path
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "internal/host/ui_events.py"


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


class Native:
    def __init__(self):
        self.foreground = 42
        self.hwnd = 42
        self.marker = {}
        self.width = 100
        self.height = 80
        self.cursor = (5, 6)
        self.GetForegroundWindow = Function(lambda: self.foreground)
        self.GetAncestor = Function(lambda hwnd, _: hwnd)
        self.GetWindowThreadProcessId = Function(self.pid)
        self.GetClientRect = Function(self.bounds)
        self.IsWindowVisible = Function(lambda _: True)
        self.IsWindow = Function(lambda _: True)
        self.IsIconic = Function(lambda _: False)
        self.SetPropW = Function(self.set_property)
        self.GetPropW = Function(lambda hwnd, name: self.marker.get((hwnd, name)))
        self.GetCursorPos = Function(self.cursor_position)
        self.ScreenToClient = Function(lambda *_: True)
        self.GetCurrentProcess = Function(lambda: 7)
        self.GetProcessTimes = Function(self.creation)
        self.EnumWindows = Function(lambda callback, arg: callback(self.hwnd, arg))

    def pid(self, _, value):
        import os
        value._obj.value = os.getpid()
        return 1

    def bounds(self, _, value):
        value._obj.left = value._obj.top = 0
        value._obj.right, value._obj.bottom = self.width, self.height
        return True

    def set_property(self, hwnd, name, value):
        self.marker[(hwnd, name)] = value
        return True

    def cursor_position(self, value):
        value._obj.x, value._obj.y = self.cursor
        return True

    def creation(self, _, created, *unused):
        created._obj.dwLowDateTime = 1234
        return True


class Window:
    width = 100
    height = 80

    def __init__(self):
        self.events = []
        self.hook = None

    def as_pointer(self):
        return 123

    def event_simulate(self, **event):
        self.events.append(event)
        if self.hook:
            self.hook(event)


class UIEventsTests(unittest.TestCase):
    def setUp(self):
        self.native = Native()
        self.window = Window()
        self.callbacks = []
        bpy = types.SimpleNamespace(
            app=types.SimpleNamespace(use_event_simulate=True, driver_namespace={}, timers=types.SimpleNamespace(register=lambda callback, **_: self.callbacks.append(callback))),
            context=types.SimpleNamespace(window_manager=types.SimpleNamespace(windows=[self.window])),
        )
        self.namespace = {"bpy": bpy}
        exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), self.namespace)
        self.enterContext(patch.object(ctypes, "WinDLL", lambda *_args, **_kwargs: self.native, create=True))
        self.enterContext(patch.object(ctypes, "WINFUNCTYPE", lambda *_: lambda f: f, create=True))
        self.enterContext(patch.object(self.namespace["time"], "time", return_value=10))
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.data = {"session_id": "exact", "request_hash": "hash", "index": 0, "deadline": 20,
                     "claim": {"run_id": "run", "request_hash": "hash"}, "nonce": "nonce"}

    def perform(self, action):
        self.data["ack_path"] = str(self.root / f"ack-{self.data['index']}.json")
        return self.namespace["ui_action"](dict(self.data, action=action))

    def poll(self):
        state = self.namespace["bpy"].app.driver_namespace["_blender_box_ui_exact"]
        return {"ready": state["ready"], "receipt": state["receipt"]}

    def acknowledge(self):
        callback = self.callbacks[-1]
        self.assertEqual(callback(), 0.0)
        self.assertFalse(self.poll()["ready"])
        self.assertIsNone(callback())
        self.assertTrue(self.poll()["ready"])

    def test_terminal_acknowledgement_is_atomic_and_identity_bound(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "ack.json"
            self.data.update(ack_path=str(path), nonce="nonce", claim={"run_id": "run", "request_hash": "hash"})
            self.namespace["ui_action"](dict(self.data, action={"type": "key", "key": "F2"}))
            callback = self.callbacks[-1]
            self.assertEqual(callback(), 0.0)
            self.assertFalse(path.exists())
            self.assertIsNone(callback())
            ack = json.loads(path.read_text())
            self.assertEqual(ack["claim"], self.data["claim"])
            self.assertEqual(ack["nonce"], "nonce")
            self.assertEqual(ack["session_id"], "exact")
            self.assertEqual(ack["receipt"]["outcome"], "queued")
            self.assertEqual(list(Path(root).iterdir()), [path])

    def test_existing_acknowledgement_is_never_replaced(self):
        self.perform({"type": "key", "key": "F2"})
        path = Path(self.data["ack_path"])
        path.write_bytes(b"existing")
        self.acknowledge()
        self.assertEqual(path.read_bytes(), b"existing")
        self.assertEqual(self.poll()["receipt"]["outcome"], "uncertain")
        self.assertEqual(self.poll()["receipt"]["error_code"], "delivery-failed")

    def test_late_callback_never_recreates_removed_run_directory(self):
        self.perform({"type": "key", "key": "F2"})
        self.root.rmdir()
        self.acknowledge()
        self.assertFalse(self.root.exists())
        self.assertEqual(self.poll()["receipt"]["outcome"], "uncertain")
        self.assertEqual(len(self.window.events), 2)

    def test_client_coordinates_and_text_keep_same_pointer(self):
        reply = self.perform({"type": "click", "x": 12, "y": 19, "button": "left"})
        self.assertFalse(reply["ready"])
        self.assertEqual(reply["receipt"]["outcome"], "pending")
        self.assertTrue(all((e["x"], e["y"]) == (12, 60) for e in self.window.events))
        self.acknowledge()
        self.assertEqual(self.poll()["receipt"]["outcome"], "queued")
        self.data["index"] = 1
        self.perform({"type": "text", "text": "é漢"})
        self.acknowledge()
        events = self.window.events[3:]
        self.assertEqual([e.get("unicode") for e in events], ["é", None, "漢", None])
        self.assertTrue(all(e["type"] == "F24" and (e["x"], e["y"]) == (12, 60) for e in events))
        self.assertNotIn("é漢", str(self.poll()))

    def test_key_first_uses_sampled_cursor_without_warping(self):
        self.perform({"type": "key", "key": "DELETE", "modifiers": ["ctrl"]})
        self.acknowledge()
        self.assertEqual([e["type"] for e in self.window.events], ["LEFT_CTRL", "DEL", "DEL", "LEFT_CTRL"])
        self.assertTrue(all((e["x"], e["y"]) == (5, 73) for e in self.window.events))
        self.assertEqual(self.native.cursor, (5, 6))

    def test_focus_loss_between_events_releases_only_bound_window(self):
        self.window.hook = lambda _: setattr(self.native, "foreground", 99)
        reply = self.perform({"type": "key", "key": "A", "modifiers": ["ctrl"]})
        self.assertEqual(reply["receipt"]["outcome"], "uncertain")
        self.assertEqual(reply["receipt"]["error_code"], "focus-lost")
        self.assertEqual([e["value"] for e in self.window.events], ["PRESS", "RELEASE"])
        self.assertFalse(self.window.events[-1]["ctrl"])
        self.assertEqual(self.native.foreground, 99)

    def test_reused_handle_or_replacement_window_is_rejected(self):
        self.perform({"type": "key", "key": "F2"})
        self.acknowledge()
        self.data["index"] = 1
        self.native.marker.clear()
        reply = self.perform({"type": "text", "text": "private"})
        self.assertEqual(reply["receipt"]["error_code"], "window-replaced")
        self.assertEqual(len(self.window.events), 2)

    def test_deadline_expires_before_injection_and_during_ack(self):
        self.data["deadline"] = 10
        reply = self.perform({"type": "text", "text": "private"})
        self.assertEqual(reply["receipt"]["outcome"], "rejected")
        self.assertEqual(reply["receipt"]["error_code"], "timed-out")
        self.assertFalse(self.window.events)
        self.data["deadline"] = 20
        self.perform({"type": "key", "key": "F2"})
        with patch.object(self.namespace["time"], "time", return_value=21):
            self.acknowledge()
        self.assertEqual(self.poll()["receipt"]["outcome"], "uncertain")

    def assert_ack_rejects(self, change, code):
        self.perform({"type": "key", "key": "F2"})
        callback = self.callbacks[-1]
        self.assertEqual(callback(), 0.0)
        change()
        self.assertIsNone(callback())
        reply = self.poll()
        self.assertTrue(reply["ready"])
        self.assertEqual(reply["receipt"]["outcome"], "uncertain")
        self.assertEqual(reply["receipt"]["error_code"], code)
        self.assertEqual(reply["receipt"]["event_count"], 2)
        self.assertEqual(len(self.window.events), 2)

    def test_ack_rechecks_foreground_after_event_delivery(self):
        self.assert_ack_rejects(lambda: setattr(self.native, "foreground", 99), "focus-lost")

    def test_ack_rechecks_handle_lifetime_after_event_delivery(self):
        self.assert_ack_rejects(self.native.marker.clear, "window-replaced")

    def test_ack_rejects_matching_native_and_blender_resize(self):
        def resize():
            self.native.width = self.window.width = 120
        self.assert_ack_rejects(resize, "coordinate-mismatch")

    def test_ack_unexpected_error_still_returns_terminal_receipt(self):
        def fail():
            raise RuntimeError("private native details")
        self.assert_ack_rejects(lambda: setattr(self.native.GetForegroundWindow, "call", fail), "delivery-failed")

    def test_batch_keeps_initial_dimensions_for_later_actions(self):
        self.perform({"type": "key", "key": "F2"})
        self.acknowledge()
        self.data["index"] = 1
        self.native.height = self.window.height = 90
        reply = self.perform({"type": "text", "text": "private"})
        self.assertEqual(reply["receipt"]["outcome"], "rejected")
        self.assertEqual(reply["receipt"]["error_code"], "coordinate-mismatch")
        self.assertEqual(len(self.window.events), 2)

    def test_no_replay_out_of_bounds_and_multiple_windows(self):
        reply = self.perform({"type": "click", "x": 100, "y": 0, "button": "left"})
        self.assertEqual(reply["receipt"]["error_code"], "out-of-bounds")
        self.assertFalse(self.window.events)
        self.namespace["bpy"].context.window_manager.windows.append(Window())
        reply = self.perform({"type": "key", "key": "F2"})
        self.assertEqual(reply["receipt"]["error_code"], "window-ambiguous")
        self.assertFalse(self.window.events)


if __name__ == "__main__":
    unittest.main()
