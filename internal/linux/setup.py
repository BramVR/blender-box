import base64
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys
import threading
import time

MAX_INPUT = 90 << 20
MAX_BINARY = 64 << 20


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(path, uid, private=False, missing=False):
    current = pathlib.Path(path)
    leaf = True
    while True:
        try:
            info = current.lstat()
        except FileNotFoundError:
            require(missing, "missing path " + str(current))
        else:
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "unsafe path type " + str(current))
            protected_sticky_parent = not leaf and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            require(info.st_uid in (0, uid) and (not info.st_mode & 0o022 or protected_sticky_parent), "unsafe path owner or mode " + str(current))
            if leaf and private:
                require(info.st_uid == uid and not info.st_mode & 0o077, "path must be private to declared UID " + str(current))
        if current.parent == current:
            break
        current = current.parent
        leaf = False


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def make_directory(path, uid):
    safe_path(path, uid, missing=True)
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        make_directory(parent, uid)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        require(stat.S_ISDIR(os.lstat(path).st_mode), "managed directory is not a directory")
    else:
        sync_directory(parent)
    safe_path(path, uid)


def read_file(path, uid, limit):
    safe_path(path, uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "unsafe or oversized managed file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, "managed file exceeds bound")
        return data
    finally:
        os.close(fd)


def atomic_write(path, data, mode, uid):
    temporary = path + ".linux-setup.tmp"
    safe_path(path, uid, missing=True)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        safe_path(temporary, uid, private=True)
        require(read_file(temporary, uid, len(data)) == data, "interrupted setup temporary needs inspection: " + temporary)
        fd = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            require(stat.S_IMODE(os.fstat(fd).st_mode) == mode, "interrupted temporary mode mismatch")
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
    os.replace(temporary, path)
    sync_directory(os.path.dirname(path))


def run(command, environment, input_data=None, timeout=30):
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(command, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    exceeded = threading.Event()
    streams = [bytearray(), bytearray()]

    def drain(stream, output):
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                remaining = 65536 - len(output)
                output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    exceeded.set()
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    return
        finally:
            stream.close()

    readers = [threading.Thread(target=drain, args=(stream, output), daemon=True)
               for stream, output in zip((process.stdout, process.stderr), streams)]
    for reader in readers:
        reader.start()
    writer = None
    if input_data is not None:
        def feed():
            try:
                process.stdin.write(input_data)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        writer = threading.Thread(target=feed, daemon=True)
    try:
        require(input_data is None or len(input_data) <= 65536, "setup child input exceeds bound")
        if writer is not None:
            writer.start()
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("setup command deadline exceeded")
        if writer is not None:
            writer.join(timeout=1)
            require(not writer.is_alive(), "setup command retained its input pipe")
        for reader in readers:
            reader.join(timeout=1)
        require(not any(reader.is_alive() for reader in readers), "setup command retained an output pipe")
        require(not exceeded.is_set(), "setup command output exceeds bound")
        return process.returncode, bytes(streams[0]), bytes(streams[1])
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def unit_state(unit, environment):
    code, output, errors = run(["/usr/bin/systemctl", "--user", "show", unit, "--no-pager",
                               "-p", "LoadState", "-p", "ActiveState", "-p", "FragmentPath", "-p", "DropInPaths", "-p", "Names"], environment)
    fields = dict(line.split("=", 1) for line in output.decode().splitlines() if "=" in line)
    require(code in (0, 1) and fields.get("ActiveState") == "inactive" and fields.get("LoadState") in ("loaded", "not-found"),
            "static user unit must be inactive; exact Session settlement is required: " + errors.decode(errors="replace"))
    require(not fields.get("DropInPaths"), "unit drop-ins are forbidden")
    return fields


def apply(document):
    config, plan = document["config"], document["plan"]
    uid, root, home = config["uid"], config["work_root"], config["home"]
    require(sys.platform == "linux" and sys.version_info[:2] == (3, 12), "requires Ubuntu system CPython 3.12")
    require(os.getuid() == os.geteuid() == uid and 1000 <= uid <= 60000, "SSH UID must equal declared desktop UID")
    require(pwd.getpwuid(uid).pw_dir == home, "configured home does not match passwd")
    require(os.environ.get("XDG_CONFIG_HOME", home + "/.config") == home + "/.config", "XDG_CONFIG_HOME conflicts with configured home")
    release = dict(line.split("=", 1) for line in pathlib.Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID", "").strip('"') == "ubuntu" and release.get("VERSION_ID", "").strip('"') == "24.04", "requires Ubuntu 24.04")
    path_pattern = re.compile(r"/[A-Za-z0-9._/-]{1,220}\Z")
    for path in (home, root, config["host_executable"], config["desktop"]["xauthority"]):
        require(path_pattern.fullmatch(path) and os.path.normpath(path) == path and not path.endswith("/"), "invalid absolute POSIX path")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.service", config["unit_name"]) is not None, "invalid static unit name")
    host_path = config["host_executable"]
    unit_path = home + "/.config/systemd/user/" + config["unit_name"]
    require(os.path.dirname(host_path) == root + "/bin", "host executable must be inside managed bin directory")
    require(plan["host_destination"] == host_path and plan["unit_destination"] == unit_path and plan["unit_name"] == config["unit_name"], "setup destination mismatch")
    binary = base64.b64decode(document["binary"], validate=True)
    unit = plan["unit_bytes"].encode()
    require(0 < len(binary) <= MAX_BINARY and len(binary) == plan["host_size"] and digest(binary) == plan["host_sha256"], "host binary size/hash mismatch")
    require(len(unit) <= 16384 and digest(unit) == plan["unit_sha256"], "static unit size/hash mismatch")
    desktop = config["desktop"]
    require(re.fullmatch(r":[0-9]{1,2}", desktop["display"]) is not None, "invalid local X11 display")
    expected_unit = ("[Unit]\nDescription=Blender Box owned Run launcher\n\n[Service]\n"
                     "Type=exec\nExitType=cgroup\nRemainAfterExit=no\nRestart=no\nKillMode=process\n"
                     "ExecStart=" + host_path + " host run-request --state-root " + root + "\n"
                     "Environment=HOME=" + home + "\nEnvironment=DISPLAY=" + desktop["display"] + "\n"
                     "Environment=XAUTHORITY=" + desktop["xauthority"] + "\n"
                     "Environment=XDG_RUNTIME_DIR=/run/user/" + str(uid) + "\n"
                     "Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + str(uid) + "/bus\n")
    require(unit == expected_unit.encode(), "static unit does not match declared configuration")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": home,
                   "XDG_RUNTIME_DIR": "/run/user/" + str(uid),
                   "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/" + str(uid) + "/bus"}
    code, output, _ = run(["/usr/bin/systemctl", "--version"], environment)
    require(code == 0 and output.startswith(b"systemd 255"), "requires systemd 255")
    safe_path(home, uid)
    safe_path(root, uid, private=True, missing=True)
    safe_path(host_path, uid, missing=True)
    safe_path(unit_path, uid, missing=True)
    make_directory(root, uid)
    safe_path(root, uid, private=True)
    lock_path = root + "/.operation.lock"
    safe_path(lock_path, uid, private=True, missing=True)
    lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o077, "unsafe operation lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sync_directory(root)
        require(not os.path.lexists(root + "/host-lock.json"), "Host Lock exists; exact Run settlement is required")
        state = unit_state(config["unit_name"], environment)
        require(state.get("FragmentPath", "") in ("", unit_path), "static unit resolves to another file")
        require(state.get("Names", "") in ("", config["unit_name"]), "static unit aliases are forbidden")
        receipt_path = root + "/.linux-setup.json"
        identity = {"schema_version": 1, "uid": uid, "work_root": root, "host_destination": host_path, "unit_destination": unit_path}
        previous = None
        initial_temporary = receipt_path + ".linux-setup.tmp"
        if not os.path.lexists(receipt_path) and os.path.lexists(initial_temporary):
            require(set(os.listdir(root)) <= {".operation.lock", ".linux-setup.json.linux-setup.tmp"}, "initial ownership temporary has unexpected accompanying artifacts")
            safe_path(initial_temporary, uid, private=True)
            initial_bytes = read_file(initial_temporary, uid, 16384)
            initial = json.loads(initial_bytes)
            require(set(initial) == set(identity) | {"installed", "pending"} and all(initial.get(key) == value for key, value in identity.items()), "initial setup ownership temporary does not match target")
            require(initial["installed"] == {} and set(initial["pending"]) == {"host_sha256", "unit_sha256"} and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in initial["pending"].values()), "initial setup ownership temporary is incomplete")
            atomic_write(receipt_path, initial_bytes, 0o600, uid)
        if os.path.lexists(receipt_path):
            previous = json.loads(read_file(receipt_path, uid, 16384))
            require(all(previous.get(key) == value for key, value in identity.items()), "setup ownership receipt belongs to another target")
        else:
            require(set(os.listdir(root)) <= {".operation.lock"}, "work root contains unrecognized artifacts without an ownership receipt")
        actual_installed = {}
        for path, key, limit in ((host_path, "host_sha256", MAX_BINARY), (unit_path, "unit_sha256", 16384)):
            if os.path.lexists(path):
                require(previous is not None, "refusing unrecognized existing artifact " + path)
                safe_path(path, uid, private=True)
                known = {previous.get("installed", {}).get(key), previous.get("pending", {}).get(key)}
                actual = digest(read_file(path, uid, limit))
                require(actual in known, "managed artifact drifted; refusing replacement " + path)
                actual_installed[key] = actual
        for path in (root + "/bin", root + "/runs", root + "/receipts"):
            safe_path(path, uid, missing=True)
        if previous is not None and os.path.lexists(initial_temporary):
            safe_path(initial_temporary, uid, private=True)
            completed = read_file(initial_temporary, uid, 16384)
            final_receipt = dict(identity, installed=previous.get("pending"))
            if completed == json.dumps(final_receipt, sort_keys=True).encode():
                require(set(actual_installed) == {"host_sha256", "unit_sha256"}
                        and actual_installed == previous.get("pending"), "completed ownership temporary does not match installed artifacts")
                atomic_write(receipt_path, completed, 0o600, uid)
        pending = {"host_sha256": plan["host_sha256"], "unit_sha256": plan["unit_sha256"]}
        receipt = dict(identity, installed=actual_installed, pending=pending)
        atomic_write(receipt_path, json.dumps(receipt, sort_keys=True).encode(), 0o600, uid)
        for path in (root + "/bin", root + "/runs", root + "/receipts", os.path.dirname(unit_path)):
            make_directory(path, uid)
        launch_lock = root + "/.launch.lock"
        if not os.path.lexists(launch_lock):
            fd = os.open(launch_lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.fsync(fd)
            os.close(fd)
            sync_directory(root)
        safe_path(launch_lock, uid, private=True)
        atomic_write(host_path, binary, 0o700, uid)
        atomic_write(unit_path, unit, 0o600, uid)
        code, _, errors = run(["/usr/bin/systemctl", "--user", "daemon-reload"], environment)
        require(code == 0, "unit reload failed; pending ownership retained: " + errors.decode(errors="replace"))
        code, _, errors = run([host_path, "host", "linux-unit-check", "--state-root", root], environment, json.dumps(config).encode())
        require(code == 0, "effective unit verification failed; pending ownership retained: " + errors.decode(errors="replace"))
        receipt = dict(identity, installed=pending)
        atomic_write(receipt_path, json.dumps(receipt, sort_keys=True).encode(), 0o600, uid)
        print(json.dumps({"schema_version": 1, "status": "applied", **pending}))
    finally:
        os.close(lock)


def main():
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    require(len(data) <= MAX_INPUT, "setup input exceeds bound")
    apply(json.loads(data))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Linux setup refused: " + str(error), file=sys.stderr)
        sys.exit(1)
