"""Nonblocking, process-held single executor lock on a local database sidecar.

The OS releases this lock on process death. Never delete/replace the lock file:
another process could then lock a different inode. Network filesystems and
multiple database aliases/hard links are outside this local-only contract.
"""

import errno
import os
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def executor_lock(database: Path):
    path = database.resolve().with_suffix(database.suffix + ".runner.lock")
    with path.open("a+b") as handle:
        # Windows byte-range locks need an existing byte. Racing appends are
        # harmless: every executor always locks the first byte, never the end.
        if path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise
            yield False
            return
        try:
            yield True
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
