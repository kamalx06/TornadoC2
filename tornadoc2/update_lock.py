"""Cross-process lock that serialises update operations.

Two update attempts running at once would race on the git index
and on the state file. The lock is a file under logs/.update/;
holding it is not advisory in the sense of blocking the other
process — the second attempt raises UpdateLockError immediately,
which the caller turns into a console message.
"""

import os
import time

try:
    from .constants import LOGS_DIR
except (ImportError, AttributeError):
    LOGS_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'logs',
    )

LOCK_DIR = os.path.join(LOGS_DIR, '.update')
LOCK_FILE = os.path.join(LOCK_DIR, 'update.lock')

# If a previous process died between acquiring the lock and
# releasing it, the file may still exist. Anything older than this
# is considered stale and can be broken.
STALE_LOCK_SECONDS = 3600


class UpdateLockError(RuntimeError):
    pass


class UpdateLock:
    """File-based exclusive lock. Context manager.

    Raises UpdateLockError if another live process holds the lock.
    A lock file whose mtime is older than STALE_LOCK_SECONDS is
    treated as stale (holder crashed) and is broken."""

    def __init__(self):
        self._fd = None

    def __enter__(self):
        os.makedirs(LOCK_DIR, exist_ok=True)
        self._break_if_stale()
        try:
            self._fd = os.open(
                LOCK_FILE,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            raise UpdateLockError(
                f'another update is in progress (lock file '
                f'{LOCK_FILE!r} exists). If no other operator is '
                f'running an update, remove the lock file and '
                f'retry.'
            )
        try:
            os.write(self._fd, str(os.getpid()).encode('ascii'))
        except OSError:
            pass
        return self

    def release(self):
        """Release the lock explicitly. Safe to call more than once.

        Needed because the restart path calls os.execv, which
        replaces the process image without running __exit__. A
        caller that is about to exec must drop the lock first or
        the lock file survives into the next process.
        """
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        try:
            os.remove(LOCK_FILE)
        except OSError:
            pass

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False

    def _break_if_stale(self):
        """Break the lock file if it cannot belong to a live
        holder other than ourselves.

        Three cases break the lock:

        1. Age exceeds STALE_LOCK_SECONDS.
        2. The recorded PID is our own. On POSIX, ``os.execv``
           preserves the PID, so an update that restarted the
           handler while inside a ``with UpdateLock()`` block
           leaves a lock file carrying the post-restart
           process's PID. That is never a legitimate live holder
           — it is the previous incarnation of this process.
        3. The recorded PID no longer maps to a running process.
        """
        try:
            mtime = os.path.getmtime(LOCK_FILE)
        except OSError:
            return

        age = time.time() - mtime
        if age >= STALE_LOCK_SECONDS:
            try:
                os.remove(LOCK_FILE)
            except OSError:
                pass
            return

        try:
            with open(LOCK_FILE, 'r', encoding='ascii') as fh:
                pid = int(fh.read().strip() or '0')
        except (OSError, ValueError):
            return

        if pid <= 0:
            return

        # Case 2: our own PID, left behind by a pre-restart execv.
        if pid == os.getpid():
            try:
                os.remove(LOCK_FILE)
            except OSError:
                pass
            return

        # Case 3: the PID is not running (POSIX only).
        if os.name != 'nt':
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                try:
                    os.remove(LOCK_FILE)
                except OSError:
                    pass
            except OSError:
                pass