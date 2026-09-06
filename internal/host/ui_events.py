import ctypes
import json
import os
import secrets
import time
import tempfile
from ctypes import wintypes


class UIRejected(Exception):
    pass


def native_window():
    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    user.GetForegroundWindow.restype = wintypes.HWND
    user.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user.GetAncestor.restype = wintypes.HWND
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.IsWindow.argtypes = [wintypes.HWND]
    user.IsIconic.argtypes = [wintypes.HWND]
    user.SetPropW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.HANDLE]
    user.GetPropW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
    user.GetPropW.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), *[ctypes.byref(t) for t in times]):
        raise UIRejected("stale-session")
    creation = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    windows = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd, _):
        pid = wintypes.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == os.getpid() and user.IsWindowVisible(hwnd) and user.GetAncestor(hwnd, 2) == hwnd:
            windows.append(hwnd)
        return True
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    if not user.EnumWindows(callback_type(visit), 0) or len(windows) != 1:
        raise UIRejected("window-ambiguous")
    hwnd = windows[0]
    bounds = wintypes.RECT()
    if not user.GetClientRect(hwnd, ctypes.byref(bounds)) or user.IsIconic(hwnd):
        raise UIRejected("window-replaced")
    return user, hwnd, creation, bounds.right - bounds.left, bounds.bottom - bounds.top


def bind_window(data, state):
    if time.time() >= data["deadline"]:
        raise UIRejected("timed-out")
    if not bpy.app.use_event_simulate:
        raise UIRejected("unsupported")
    windows = list(bpy.context.window_manager.windows)
    if len(windows) != 1:
        raise UIRejected("window-ambiguous")
    window = windows[0]
    user, hwnd, creation, width, height = native_window()
    if width < 1 or height < 1 or width > 32768 or height > 32768 or width != window.width or height != window.height:
        raise UIRejected("coordinate-mismatch")
    if state is None:
        if data["index"] != 0:
            raise UIRejected("window-replaced")
        marker = secrets.randbits(62) + 1
        property_name = "BlenderBox.UI." + data["session_id"]
        if not user.SetPropW(hwnd, property_name, marker):
            raise UIRejected("unsupported")
        state = {"session_id": data["session_id"], "request_hash": data["request_hash"], "hwnd": hwnd,
                 "creation": creation, "window": window, "pointer": window.as_pointer(), "width": width, "height": height,
                 "marker": marker, "property": property_name, "next": 0, "receipt": None, "ready": False}
        user.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        user.ScreenToClient.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
        point = wintypes.POINT()
        if not user.GetCursorPos(ctypes.byref(point)) or not user.ScreenToClient(hwnd, ctypes.byref(point)):
            raise UIRejected("coordinate-mismatch")
        state["point"] = (point.x, height - 1 - point.y)
    if (state["session_id"] != data["session_id"] or state["request_hash"] != data["request_hash"] or
        state["hwnd"] != hwnd or state["creation"] != creation or state["pointer"] != window.as_pointer() or
        state["window"] != window or user.GetPropW(hwnd, state["property"]) != state["marker"]):
        raise UIRejected("window-replaced")
    if width != state["width"] or height != state["height"]:
        raise UIRejected("coordinate-mismatch")
    if user.GetForegroundWindow() != hwnd:
        raise UIRejected("focus-lost")
    return state, window, width, height


def events_for(action, width, height):
    kind = action["type"]
    if kind == "click":
        x, y = action["x"], action["y"]
        if not (0 <= x < width and 0 <= y < height):
            raise UIRejected("out-of-bounds")
        button = {"left": "LEFTMOUSE", "right": "RIGHTMOUSE", "middle": "MIDDLEMOUSE"}[action["button"]]
        pos = {"x": x, "y": height - 1 - y}
        return [dict(type="MOUSEMOVE", value="NOTHING", **pos), dict(type=button, value="PRESS", **pos), dict(type=button, value="RELEASE", **pos)]
    if kind == "text":
        return [event for scalar in action["text"] for event in ({"type": "F24", "value": "PRESS", "unicode": scalar}, {"type": "F24", "value": "RELEASE"})]
    names = {"ENTER": "RET", "BACKSPACE": "BACK_SPACE", "DELETE": "DEL", "PAGEUP": "PAGE_UP", "PAGEDOWN": "PAGE_DOWN", "LEFT": "LEFT_ARROW", "RIGHT": "RIGHT_ARROW", "UP": "UP_ARROW", "DOWN": "DOWN_ARROW"}
    names.update(dict(zip("0123456789", ("ZERO", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT", "NINE"))))
    modifiers = [m for m in ("ctrl", "shift", "alt") if m in action.get("modifiers", [])]
    modifier_types = {"ctrl": "LEFT_CTRL", "shift": "LEFT_SHIFT", "alt": "LEFT_ALT"}
    key = names.get(action["key"], action["key"])
    active = {}
    events = []
    for modifier in modifiers:
        active[modifier] = True
        events.append(dict(type=modifier_types[modifier], value="PRESS", **active))
    events.extend([dict(type=key, value="PRESS", **active), dict(type=key, value="RELEASE", **active)])
    for modifier in reversed(modifiers):
        active[modifier] = False
        events.append(dict(type=modifier_types[modifier], value="RELEASE", **active))
    return events


def publish_acknowledgement(data, receipt):
    path = data["ack_path"]
    if os.path.lexists(path):
        raise UIRejected("delivery-failed")
    content = json.dumps({"schema_version": 1, "claim": data["claim"], "session_id": data["session_id"],
                          "nonce": data["nonce"], "receipt": receipt}, separators=(",", ":")).encode("utf-8")
    if len(content) > 16384:
        raise UIRejected("delivery-failed")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=os.path.dirname(path), prefix=".ack-", delete=False) as file:
            temporary = file.name
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        # Windows rename atomically publishes without replacing an existing receipt.
        os.rename(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)


def ui_action(data):
    namespace = bpy.app.driver_namespace
    state_key = "_blender_box_ui_" + data["session_id"]
    state = namespace.get(state_key)
    action = data["action"]
    receipt = {"index": data["index"], "kind": action["type"], "session_id": data["session_id"], "outcome": "pending", "event_count": 0}
    held = []
    sent = 0
    attempted = False
    try:
        state, window, width, height = bind_window(data, state)
        namespace[state_key] = state
        if state["next"] != data["index"] or (state["receipt"] is not None and not state["ready"]):
            raise UIRejected("delivery-unknown")
        receipt["window"] = {"width": width, "height": height}
        events = events_for(action, width, height)
        if action["type"] == "click":
            state["point"] = (action["x"], height - 1 - action["y"])
        x, y = state["point"]
        if not (0 <= x < width and 0 <= y < height):
            raise UIRejected("out-of-bounds")
        for event in events:
            event.update(x=x, y=y)
        state["receipt"] = receipt
        state["ready"] = False
        state["next"] += 1
        for event in events:
            bind_window(data, state)
            attempted = True
            window.event_simulate(**event)
            sent += 1
            if event["value"] == "PRESS":
                held.append(event["type"])
            elif event["value"] == "RELEASE" and event["type"] in held:
                held.remove(event["type"])
        # Two timer traversals guarantee an intervening event-handler pass.
        passes = [0]
        def acknowledged():
            passes[0] += 1
            if passes[0] < 2:
                return 0.0
            try:
                bind_window(data, state)
                receipt["outcome"] = "queued"
            except Exception as failure:
                receipt["outcome"] = "uncertain"
                receipt["error_code"] = str(failure) if isinstance(failure, UIRejected) else "delivery-failed"
            finally:
                receipt["event_count"] = sent
                state["ready"] = True
            try:
                publish_acknowledgement(data, receipt)
            except Exception:
                receipt["outcome"] = "uncertain"
                receipt["error_code"] = "delivery-failed"
            return None
        bpy.app.timers.register(acknowledged, first_interval=0.0)
        return {"schema_version": 1, "ready": False, "receipt": receipt}
    except Exception as failure:
        for event_type in reversed(held):
            try:
                window.event_simulate(type=event_type, value="RELEASE", x=state["point"][0], y=state["point"][1], ctrl=False, shift=False, alt=False)
                sent += 1
            except Exception:
                pass
        receipt["outcome"] = "uncertain" if attempted else "rejected"
        receipt["event_count"] = sent
        receipt["error_code"] = str(failure) if isinstance(failure, UIRejected) else "delivery-failed"
        if state is not None:
            state["receipt"] = receipt
            state["ready"] = True
        return {"schema_version": 1, "ready": True, "receipt": receipt}
