"""Daemon lifecycle helpers for the team server.

The child process is still the same interpreter and argv with a hidden
marker. This module owns the parts that must be identical on every
launch: the instance lock, pidfile, rotating log, readiness pipe,
heartbeat and cleanup.

Security posture:

  * ``umask 077`` in the child.
  * lock/log/pid/status are created 0600 under a 0700 directory.
  * The parent holds the instance lock until the child has inherited
    it, so two simultaneous launches cannot both start.
  * The readiness pipe is a single inherited fd, not a polling
    guess.
  * A stale pidfile or socket is only removed after a liveness probe.
"""

from __future__ import annotations

import errno
import json
import os
import select
import signal
import socket
import sys
import threading
import time

try:
    import fcntl
except ImportError:                       # Windows
    fcntl = None

PID_NAME = 'tornadoc2.pid'
LOCK_NAME = 'tornadoc2.lock'
LOG_NAME = 'console.log'
SOCKET_NAME = 'tornadoc2.sock'
STATUS_NAME = 'tornadoc2.status'
LOG_MAX = 5 * 1024 * 1024
LOG_BACKUPS = 3
READY_ENV = 'TORNADOC2_DAEMON_READY_FD'
LOCK_ENV = 'TORNADOC2_DAEMON_LOCK_FD'


def runtime_dir() -> str:
    base = os.environ.get('XDG_RUNTIME_DIR')
    uid = os.getuid() if hasattr(os, 'getuid') else 0
    path = os.path.join(base or f'/tmp/tornadoc2-{uid}')
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def pid_path(rt: str) -> str:
    return os.path.join(rt, PID_NAME)


def lock_path(rt: str) -> str:
    return os.path.join(rt, LOCK_NAME)


def log_path(rt: str) -> str:
    return os.path.join(rt, LOG_NAME)


def status_path(rt: str) -> str:
    return os.path.join(rt, STATUS_NAME)


# ----------------------------------------------------------------------
# Lock and pid


class InstanceLock:
    """Exclusive ``flock`` held for the process lifetime."""

    def __init__(self, path: str):
        self.path = path
        self.fd = None

    def acquire(self) -> bool:
        if fcntl is None:
            return True
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise
        self.fd = fd
        return True

    def adopt(self, fd: int) -> None:
        self.fd = fd

    def release(self, unlock: bool = True) -> None:
        if self.fd is None:
            return
        try:
            if unlock and fcntl is not None:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.fd = None


def read_pid(path: str):
    try:
        with open(path, 'r', encoding='ascii') as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _cmdline(pid: int):
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as fh:
            return fh.read().replace(b'\x00', b' ').decode(
                'utf-8', 'replace')
    except OSError:
        return None


def pid_is_tornadoc2(pid: int):
    """True/False from /proc or ps, None when the platform cannot tell."""
    if pid is None:
        return False
    cmd = _cmdline(pid)
    if cmd is not None:
        return 'tornadoc2' in cmd
    try:
        import subprocess
        out = subprocess.run(
            ['ps', '-o', 'command=', '-p', str(pid)],
            capture_output=True, text=True, timeout=2.0)
        if out.returncode != 0:
            return None
        return 'tornadoc2' in out.stdout
    except Exception:
        return None


def pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def write_pid(path: str, pid: int) -> None:
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='ascii') as fh:
        fh.write(f'{pid}\n')
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def remove_file(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


# ----------------------------------------------------------------------
# Log


def rotate_log(path: str, max_bytes: int = LOG_MAX,
               backups: int = LOG_BACKUPS) -> None:
    try:
        if os.path.getsize(path) < max_bytes:
            return
    except OSError:
        return
    for i in range(backups - 1, 0, -1):
        src = f'{path}.{i}'
        dst = f'{path}.{i + 1}'
        if os.path.exists(src):
            try:
                os.replace(src, dst)
            except OSError:
                pass
    try:
        os.replace(path, f'{path}.1')
    except OSError:
        pass


def open_log(path: str):
    rotate_log(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return os.fdopen(fd, 'ab', buffering=0)


# ----------------------------------------------------------------------
# Readiness


def child_env(base_env: dict, ready_fd: int, lock_fd: int) -> dict:
    env = dict(base_env)
    env[READY_ENV] = str(ready_fd)
    env[LOCK_ENV] = str(lock_fd)
    return env


def notify_ready(fd: int, pid: int) -> None:
    if fd is None:
        return
    try:
        os.write(fd, f'READY {pid}\n'.encode('ascii'))
        os.close(fd)
    except OSError:
        pass


def notify_error(fd: int, message: str) -> None:
    if fd is None:
        return
    try:
        os.write(fd, b'ERROR ' + str(message)[:300].encode(
            'utf-8', 'replace') + b'\n')
        os.close(fd)
    except OSError:
        pass


def wait_ready(read_fd: int, proc, timeout: float) -> tuple:
    """Return (ok, message). Blocks on the pipe, never on the pidfile."""
    deadline = time.monotonic() + timeout
    buf = b''
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False, (f'child exited (code '
                           f'{getattr(proc, "returncode", "?")})')
        left = max(0.0, deadline - time.monotonic())
        try:
            ready, _, _ = select.select([read_fd], [], [], min(left, 0.5))
        except (OSError, ValueError):
            break
        if not ready:
            continue
        try:
            chunk = os.read(read_fd, 512)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if b'\n' in buf:
            line = buf.split(b'\n', 1)[0].decode('utf-8', 'replace')
            if line.startswith('READY '):
                return True, line
            if line.startswith('ERROR '):
                return False, line[6:]
    return False, 'no readiness signal'


# ----------------------------------------------------------------------
# Parent


def _refuse_existing(rt: str) -> bool:
    pid = read_pid(pid_path(rt))
    if pid and pid_alive(pid):
        ours = pid_is_tornadoc2(pid)
        if ours is not False:
            print(f'[daemon] already running (pid {pid}); '
                  f'pidfile={pid_path(rt)}')
            return True
    if pid:
        remove_file(pid_path(rt))
    return False


def daemonize(argv, *, socket_path: str, rt: str = None,
              ready_timeout: float = 20.0, logfile: str = None) -> int:
    """Spawn the detached child. Parent returns an exit code."""
    import subprocess

    rt = rt or runtime_dir()
    pidfile = pid_path(rt)
    logfile = logfile or log_path(rt)

    if _refuse_existing(rt):
        return 1

    lock = InstanceLock(lock_path(rt))
    try:
        if not lock.acquire():
            print('[daemon] another launch holds the instance lock')
            return 1
    except OSError as exc:
        print(f'[daemon] cannot open instance lock: {exc}')
        return 1

    try:
        log = open_log(logfile)
    except OSError as exc:
        lock.release()
        print(f'[daemon] cannot open logfile {logfile}: {exc}')
        return 1

    ready_r, ready_w = os.pipe()
    os.set_inheritable(ready_r, False)
    os.set_inheritable(ready_w, True)

    child_argv = [sys.executable] + [a for a in argv if a != '--daemon']
    child_argv.append('--_daemon-child')
    env = child_env(os.environ, ready_w, lock.fd)
    try:
        proc = subprocess.Popen(
            child_argv,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            close_fds=True,
            start_new_session=True,
            env=env,
            pass_fds=(ready_w, lock.fd),
        )
    except Exception as exc:
        os.close(ready_r)
        os.close(ready_w)
        log.close()
        lock.release()
        print(f'[daemon] spawn failed: {exc}')
        return 1
    finally:
        try:
            log.close()
        except Exception:
            pass

    os.close(ready_w)
    # The child holds the same open-file description. Unlocking here
    # would drop the lock for both; close only.
    lock.release(unlock=False)
    ok, message = wait_ready(ready_r, proc, ready_timeout)
    try:
        os.close(ready_r)
    except OSError:
        pass

    if not ok:
        print(f'[daemon] {message}; see {logfile}')
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(3)
            except Exception:
                pass
        return 1

    print(f'[daemon] starting pid={proc.pid}')
    print(f'[daemon] logfile {logfile}')
    print(f'[daemon] console socket {socket_path}')
    print(f'[daemon] attach with: {sys.executable} {sys.argv[0]} console')
    print(f'[daemon] stop with:   kill $(cat {pidfile})')
    print('[daemon] ready')
    return 0


# ----------------------------------------------------------------------
# Child


def adopted_lock_fd():
    raw = os.environ.pop(LOCK_ENV, '')
    try:
        return int(raw) if raw else None
    except ValueError:
        return None


def ready_fd():
    raw = os.environ.pop(READY_ENV, '')
    try:
        return int(raw) if raw else None
    except ValueError:
        return None


def socket_is_live(path: str) -> bool:
    if not os.path.exists(path):
        return False
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.5)
        probe.connect(path)
        return True
    except OSError:
        return False
    finally:
        probe.close()


class Heartbeat:
    def __init__(self, path: str, handler):
        self.path = path
        self.handler = handler
        self.stop = threading.Event()
        self.thread = None

    def _payload(self) -> dict:
        mgr = getattr(self.handler, '_listener_manager', None)
        listeners = 0
        try:
            if mgr is not None:
                listeners = len(mgr.list())
        except Exception:
            pass
        return {
            'pid': os.getpid(),
            'ts': time.time(),
            'state': 'running',
            'listeners': listeners,
        }

    def _write(self):
        tmp = self.path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(self._payload(), fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def start(self):
        self._write()

        def loop():
            while not self.stop.wait(5.0):
                self._write()

        self.thread = threading.Thread(
            target=loop, daemon=True, name='daemon-heartbeat')
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(1.0)
        remove_file(self.path)


def install_signals(on_term, on_hup):
    def _term(_sig, _frame):
        on_term()

    def _hup(_sig, _frame):
        try:
            on_hup()
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, _hup)
