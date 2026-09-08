from contextlib import contextmanager
import os
from pathlib import Path
import stat
import uuid

import proof_controller as model


class LocalFiles:
    read = staticmethod(model.read_private)
    @staticmethod
    def publish(*args, **kwargs):
        return model.publish(*args, **kwargs)
    directory = staticmethod(model.private_directory)

    @staticmethod
    def exists(path):
        return path.exists() or path.is_symlink()

    @staticmethod
    def entries(path):
        return list(path.iterdir())

    @staticmethod
    @contextmanager
    def scan(path):
        model.no_links(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            model.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                          and info.st_mode & 0o077 == 0, "private-directory-permissions")
            with os.scandir(fd) as entries:
                yield entries
        finally:
            os.close(fd)

    @contextmanager
    def locked(self, root):
        self.directory(root)
        fd = os.open(root / "fixture.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            model.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                          and info.st_mode & 0o077 == 0 and info.st_nlink == 1, "private-file-invalid")
            model.fcntl.flock(fd, model.fcntl.LOCK_EX | model.fcntl.LOCK_NB)
            yield
        except BlockingIOError as error:
            raise model.ControllerError("fixture-busy") from error
        finally:
            os.close(fd)


class PendingPublication(model.ControllerError):
    def __init__(self):
        super().__init__("private-publication-pending")


class RootedFiles:
    def __init__(self, root, uid, gid, *, ancestor_uid=0):
        self.root, self.uid, self.gid = Path(root), uid, gid
        model.require(self.root.is_absolute(), "unsafe-private-path")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for index, part in enumerate(self.root.parts[1:]):
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                info = os.fstat(fd)
                final = index == len(self.root.parts) - 2
                model.require(info.st_uid == (uid if final else ancestor_uid)
                              and info.st_mode & (0o077 if final else 0o022) == 0,
                              "private-directory-permissions")
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        os.close(self.fd)

    def relative(self, path):
        try:
            parts = Path(path).relative_to(self.root).parts
        except ValueError as error:
            raise model.ControllerError("unsafe-private-path") from error
        model.require(all(part not in ("", ".", "..") and "/" not in part for part in parts), "unsafe-private-path")
        return parts

    def check_directory(self, fd):
        info = os.fstat(fd)
        model.require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid
                      and info.st_mode & 0o077 == 0, "private-directory-permissions")

    @contextmanager
    def opened(self, parts):
        fd = os.dup(self.fd)
        try:
            self.check_directory(fd)
            for part in parts:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                self.check_directory(fd)
            yield fd
        finally:
            os.close(fd)

    def directory(self, path, create=False):
        parts = self.relative(path)
        if create:
            model.require(parts, "unsafe-private-path")
            with self.opened(parts[:-1]) as parent:
                os.mkdir(parts[-1], 0o700, dir_fd=parent)
                fd = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    model.require(os.fstat(fd).st_uid == os.getuid(), "private-directory-changed")
                    os.fchown(fd, self.uid, self.gid)
                    self.check_directory(fd)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)
        else:
            with self.opened(parts):
                pass

    def read(self, path, limit=model.MAX_FILE):
        parts = self.relative(path)
        model.require(parts, "unsafe-private-path")
        with self.opened(parts[:-1]) as parent:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                model.require(stat.S_ISREG(before.st_mode) and before.st_uid == self.uid
                              and before.st_mode & 0o077 == 0
                              and 0 < before.st_size <= limit, "private-file-invalid")
                if before.st_nlink == 2:
                    raise PendingPublication()
                model.require(before.st_nlink == 1, "private-file-invalid")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read(limit + 1)
                after = os.fstat(fd)
                named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                model.require(len(data) == before.st_size and before.st_mtime_ns == after.st_mtime_ns
                              and before.st_ctime_ns == after.st_ctime_ns and os.path.samestat(after, named),
                              "private-file-changed")
                return data
            finally:
                os.close(fd)

    def publish(self, path, content, exclusive=True, mode=0o600):
        model.require(isinstance(content, bytes) and 0 < len(content) <= model.MAX_FILE and mode == 0o600,
                      "invalid-document")
        parts = self.relative(path)
        model.require(parts, "unsafe-private-path")
        with self.opened(parts[:-1]) as parent:
            temporary = ".publish-" + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
            try:
                os.fchown(fd, self.uid, self.gid)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(fd)
                if exclusive:
                    os.link(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                else:
                    os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
            finally:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
            os.fsync(parent)

    def exists(self, path):
        parts = self.relative(path)
        if not parts:
            return True
        try:
            with self.opened(parts[:-1]) as parent:
                os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def entries(self, path):
        with self.opened(self.relative(path)) as fd:
            return [Path(path) / name for name in os.listdir(fd)]

    @contextmanager
    def scan(self, path):
        with self.opened(self.relative(path)) as fd:
            with os.scandir(fd) as entries:
                yield entries

    @contextmanager
    def locked(self, root):
        model.require(root == self.root and self.uid == os.getuid(), "private-directory-permissions")
        with self.opened(()) as parent:
            fd = os.open("fixture.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
            try:
                info = os.fstat(fd)
                model.require(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid
                              and info.st_mode & 0o077 == 0 and info.st_nlink == 1, "private-file-invalid")
                model.fcntl.flock(fd, model.fcntl.LOCK_EX | model.fcntl.LOCK_NB)
                yield
            except BlockingIOError as error:
                raise model.ControllerError("fixture-busy") from error
            finally:
                os.close(fd)


class FixtureFiles:
    def __init__(self, *capabilities):
        self.capabilities = capabilities

    def capability(self, path):
        matches = [cap for cap in self.capabilities if Path(path).is_relative_to(cap.root)]
        model.require(len(matches) == 1, "unsafe-private-path")
        return matches[0]

    def read(self, path, limit=model.MAX_FILE):
        return self.capability(path).read(path, limit)

    def publish(self, path, content, exclusive=True, mode=0o600):
        self.capability(path).publish(path, content, exclusive, mode)

    def directory(self, path, create=False):
        self.capability(path).directory(path, create)

    def exists(self, path):
        return self.capability(path).exists(path)

    def entries(self, path):
        return self.capability(path).entries(path)

    def scan(self, path):
        return self.capability(path).scan(path)

    def locked(self, root):
        return self.capability(root).locked(root)
