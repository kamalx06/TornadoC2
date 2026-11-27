"""Daemon helpers: lock, pidfile, readiness, logs, heartbeat."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

from support import ROOT  # noqa: F401 - sets sys.path
from tornadoc2 import daemon


class DaemonTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.rt = self.tmp.name
        self._old_umask = os.umask(0o077)

    def tearDown(self):
        os.umask(self._old_umask)
        self.tmp.cleanup()

    def test_lock_is_exclusive_and_released(self):
        a = daemon.InstanceLock(daemon.lock_path(self.rt))
        b = daemon.InstanceLock(daemon.lock_path(self.rt))
        self.assertTrue(a.acquire())
        self.assertFalse(b.acquire())
        a.release()
        self.assertTrue(b.acquire())
        b.release()

    def test_pidfile_is_atomic_and_0600(self):
        path = daemon.pid_path(self.rt)
        daemon.write_pid(path, 4321)
        self.assertEqual(daemon.read_pid(path), 4321)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertFalse(os.path.exists(path + '.tmp'))

    def test_rotate_keeps_three_backups(self):
        path = os.path.join(self.rt, 'console.log')
        with open(path, 'wb') as fh:
            fh.write(b'x' * 40)
        for _ in range(5):
            daemon.rotate_log(path, max_bytes=10, backups=3)
            with open(path, 'wb') as fh:
                fh.write(b'y' * 40)
        self.assertTrue(os.path.exists(path + '.1'))
        self.assertTrue(os.path.exists(path + '.3'))
        self.assertFalse(os.path.exists(path + '.4'))

    def test_open_log_is_0600_and_appends(self):
        path = os.path.join(self.rt, 'console.log')
        with daemon.open_log(path) as fh:
            fh.write(b'a')
        with daemon.open_log(path) as fh:
            fh.write(b'b')
        self.assertEqual(open(path, 'rb').read(), b'ab')
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_wait_ready_success(self):
        r, w = os.pipe()
        proc = SimpleNamespace(poll=lambda: None)

        def child():
            os.write(w, b'READY 7\n')

        threading.Thread(target=child).start()
        ok, msg = daemon.wait_ready(r, proc, 1.0)
        os.close(r)
        os.close(w)
        self.assertTrue(ok)
        self.assertEqual(msg, 'READY 7')

    def test_wait_ready_error(self):
        r, w = os.pipe()
        proc = SimpleNamespace(poll=lambda: None)
        os.write(w, b'ERROR boom\n')
        ok, msg = daemon.wait_ready(r, proc, 2.0)
        os.close(r)
        os.close(w)
        self.assertFalse(ok)
        self.assertEqual(msg, 'boom')

    def test_wait_ready_child_exit(self):
        r, w = os.pipe()
        proc = SimpleNamespace(poll=lambda: 1)
        ok, msg = daemon.wait_ready(r, proc, 2.0)
        os.close(r)
        os.close(w)
        self.assertFalse(ok)
        self.assertIn('exited', msg)

    def test_socket_liveness_probe(self):
        path = os.path.join(self.rt, 'x.sock')
        self.assertFalse(daemon.socket_is_live(path))
        srv = __import__('socket').socket(
            __import__('socket').AF_UNIX,
            __import__('socket').SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)
        try:
            self.assertTrue(daemon.socket_is_live(path))
        finally:
            srv.close()

    def test_heartbeat_writes_status(self):
        handler = SimpleNamespace(
            _listener_manager=SimpleNamespace(
                list=lambda: [{'id': 'a'}, {'id': 'b'}]))
        hb = daemon.Heartbeat(daemon.status_path(self.rt), handler)
        hb._write()
        data = json.load(open(daemon.status_path(self.rt),
                              encoding='utf-8'))
        self.assertEqual(data['listeners'], 2)
        self.assertEqual(data['pid'], os.getpid())


class DaemonizeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.rt = self.tmp.name
        self.script = os.path.join(self.rt, 'child.py')
        with open(self.script, 'w', encoding='utf-8') as fh:
            fh.write(
                'import os, time\n'
                'fd = int(os.environ[daemon_env])\n'
                if False else
                'import os, time\n'
                'fd = int(os.environ["TORNADOC2_DAEMON_READY_FD"])\n'
                'os.write(fd, f"READY {os.getpid()}\\n".encode())\n'
                'time.sleep(0.6)\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_daemonize_reports_ready_and_writes_log(self):
        sock = os.path.join(self.rt, 's.sock')
        code = daemon.daemonize(
            [self.script], socket_path=sock, rt=self.rt, ready_timeout=5)
        self.assertEqual(code, 0)
        time.sleep(1.0)
        log = daemon.log_path(self.rt)
        self.assertTrue(os.path.exists(log))
        self.assertEqual(stat.S_IMODE(os.stat(log).st_mode), 0o600)

    def test_daemonize_refuses_when_locked(self):
        lock = daemon.InstanceLock(daemon.lock_path(self.rt))
        self.assertTrue(lock.acquire())
        try:
            code = daemon.daemonize(
                [self.script], socket_path='/tmp/x.sock',
                rt=self.rt, ready_timeout=2)
        finally:
            lock.release()
        self.assertEqual(code, 1)


if __name__ == '__main__':
    unittest.main()
