"""Bridge handshake, allowlist, token and framing."""
import json
import os
import socket
import struct
import subprocess
import sys
import time
import unittest

from support import ROOT, TempState


class Bridge:
    def __init__(self):
        env = dict(os.environ)
        env['XDG_RUNTIME_DIR'] = os.path.join(os.getcwd(), 'run')
        os.makedirs(env['XDG_RUNTIME_DIR'], exist_ok=True)
        self.p = subprocess.Popen(
            [sys.executable, '-m', 'tornado_client.bridge'],
            cwd=ROOT, env={**env, 'PYTHONPATH': os.path.join(
                ROOT, 'client')},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.p.stdout.readline()
        if not line.startswith('READY '):
            raise RuntimeError(f'bridge did not start: {line!r}')
        self.info = json.loads(line[6:])
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def open(self):
        self.sock.connect(self.info['socket'])

    def send(self, obj):
        raw = json.dumps(obj).encode()
        self.sock.sendall(struct.pack('>I', len(raw)) + raw)

    def recv(self):
        head = b''
        while len(head) < 4:
            head += self.sock.recv(4 - len(head))
        n = struct.unpack('>I', head)[0]
        body = b''
        while len(body) < n:
            body += self.sock.recv(n - len(body))
        return json.loads(body)

    def hello(self, token=None):
        self.send({'id': 1, 'method': 'hello',
                   'params': {'token': token or self.info['token']}})
        return self.recv()

    def stop(self):
        try:
            self.sock.close()
        except Exception:
            pass
        self.p.terminate()
        try:
            self.p.wait(3)
        except subprocess.TimeoutExpired:
            self.p.kill()


class BridgeTest(TempState):
    def setUp(self):
        super().setUp()
        self.b = Bridge()

    def tearDown(self):
        self.b.stop()
        super().tearDown()

    def test_ready_and_handshake(self):
        self.b.open()
        r = self.b.hello()
        self.assertTrue(r['ok'])
        self.assertEqual(r['result']['proto'], 1)
        self.assertEqual(os.stat(self.b.info['socket']).st_mode & 0o777,
                         0o600)

    def test_bad_token(self):
        self.b.open()
        self.b.send({'id': 1, 'method': 'hello',
                     'params': {'token': 'nope'}})
        r = self.b.recv()
        self.assertFalse(r['ok'])
        self.assertEqual(r['code'], 'bad_token')

    def test_unknown_method_and_allowlist(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 2, 'method': 'ping', 'params': {}})
        self.assertTrue(self.b.recv()['ok'])
        self.b.send({'id': 3, 'method': 'exec', 'params': {}})
        r = self.b.recv()
        self.assertEqual(r['code'], 'unknown_method')

    def test_not_connected(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 4, 'method': 'beacons', 'params': {}})
        r = self.b.recv()
        self.assertFalse(r['ok'])
        self.assertEqual(r['code'], 'not_connected')

    def test_bad_params(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 5, 'method': 'task', 'params': {'id': 'x',
                                                           'verb': 'ls'}})
        r = self.b.recv()
        self.assertEqual(r['code'], 'bad_params')

    def test_new_read_methods_validate(self):
        self.b.open()
        self.b.hello()
        for mid, params in ((10, {'id': 'lst_a', 'x': 'y'}),
                            (11, {'limit': 'x'}),
                            (12, {'limit': 10})):
            method = {10: 'listeners.get', 11: 'chat.history',
                      12: 'loot.list'}[mid]
            self.b.send({'id': mid, 'method': method, 'params': params})
            r = self.b.recv()
            # Not connected, so validation errors or connection errors.
            self.assertFalse(r['ok'])
        self.b.send({'id': 13, 'method': 'listeners.get',
                     'params': {'id': 'lst_a'}})
        self.assertEqual(self.b.recv()['code'], 'not_connected')

    def test_listener_id_validation(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 20, 'method': 'listeners.get',
                     'params': {'id': 'bad id!'}})
        self.assertEqual(self.b.recv()['code'], 'bad_params')

    def test_chat_limit_validation(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 21, 'method': 'chat.history',
                     'params': {'limit': 'x'}})
        self.assertEqual(self.b.recv()['code'], 'bad_params')

    def test_action_validation(self):
        self.b.open()
        self.b.hello()
        cases = [
            (30, 'beacon.alias', {'id': 1, 'alias': 5}, 'bad_params'),
            (31, 'beacon.tag', {'id': 1, 'tag': ''}, 'bad_params'),
            (32, 'jump', {'id': 1, 'method': 'nope', 'target': 'h'},
             'bad_params'),
            (33, 'jump', {'id': 1, 'method': 'wmi', 'target': ''},
             'bad_params'),
            (34, 'armory.install', {'names': []}, 'bad_params'),
            (35, 'armory.uninstall', {'names': 'x'}, 'bad_params'),
        ]
        for mid, method, params, want in cases:
            self.b.send({'id': mid, 'method': method, 'params': params})
            self.assertEqual(self.b.recv()['code'], want)

    def test_action_methods_not_connected(self):
        self.b.open()
        self.b.hello()
        for mid, method, params in (
                (40, 'task.result', {'id': 1, 'taskId': 't'}),
                (41, 'listener.start', {'id': 'lst_a'}),
                (42, 'beacon.forget', {'id': 1}),
                (43, 'export.ioc', {})):
            self.b.send({'id': mid, 'method': method, 'params': params})
            self.assertEqual(self.b.recv()['code'], 'not_connected')

    def test_ai_question_validation(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 50, 'method': 'ai.ask', 'params': {'question': ''}})
        self.assertEqual(self.b.recv()['code'], 'bad_params')
        self.b.send({'id': 51, 'method': 'ai.ask',
                     'params': {'question': 'x' * 4001}})
        self.assertEqual(self.b.recv()['code'], 'bad_params')
        self.b.send({'id': 52, 'method': 'ai.ask',
                     'params': {'question': 'hi'}})
        self.assertEqual(self.b.recv()['code'], 'not_connected')

    def test_chat_and_note_validation(self):
        self.b.open()
        self.b.hello()
        for mid, method, params in (
                (60, 'chat.send', {'text': ''}),
                (61, 'chat.send', {'text': 'x' * 4097}),
                (62, 'beacon.note', {'id': 1, 'op': 'add', 'text': ''}),
                (63, 'beacon.note', {'id': 1, 'op': 'nope'})):
            self.b.send({'id': mid, 'method': method, 'params': params})
            self.assertEqual(self.b.recv()['code'], 'bad_params')

    def test_listener_write_validation(self):
        self.b.open()
        self.b.hello()
        cases = [
            (70, 'listener.create', {'spec': {'type': 'nope', 'name': 'a', 'port': 1}}, 'bad_params'),
            (71, 'listener.create', {'spec': {'type': 'http', 'name': ' ', 'port': 1}}, 'bad_params'),
            (72, 'listener.create', {'spec': {'type': 'http', 'name': 'a', 'port': 'x'}}, 'bad_params'),
            (73, 'listener.update', {'id': 'lst_a', 'patch': {}}, 'bad_params'),
            (74, 'listener.update', {'patch': {'name': 'x'}}, 'bad_params'),
            (75, 'listener.delete', {}, 'bad_params'),
        ]
        for mid, method, params, want in cases:
            self.b.send({'id': mid, 'method': method, 'params': params})
            self.assertEqual(self.b.recv()['code'], want)

    def test_listener_write_not_connected(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 80, 'method': 'listener.create', 'params': {
            'spec': {'type': 'http', 'name': 'a', 'port': 443}}})
        self.assertEqual(self.b.recv()['code'], 'not_connected')
        self.b.send({'id': 81, 'method': 'listeners.certs', 'params': {}})
        self.assertEqual(self.b.recv()['code'], 'not_connected')

    def test_transfer_and_build_validation(self):
        self.b.open()
        self.b.hello()
        cases = [
            (90, 'upload.start', {'id': 1, 'remote': '/x'}, 'bad_params'),
            (91, 'upload.start', {'id': 1, 'local': '/nope', 'remote': '/x'}, 'bad_params'),
            (92, 'download.start', {'id': 1}, 'bad_params'),
            (93, 'job.cancel', {}, 'bad_params'),
            (94, 'job.cancel', {'id': 'job_x'}, 'not_found'),
            (95, 'build.start', {'out': '/tmp/x'}, 'bad_params'),
            (96, 'build.start', {'config': {}}, 'bad_params'),
        ]
        for mid, method, params, want in cases:
            self.b.send({'id': mid, 'method': method, 'params': params})
            self.assertEqual(self.b.recv()['code'], want)

    def test_job_list_empty(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 97, 'method': 'job.list', 'params': {}})
        r = self.b.recv()
        self.assertTrue(r['ok'])
        self.assertEqual(r['result']['jobs'], [])

    def test_session_action_validation(self):
        self.b.open()
        self.b.hello()
        cases = [
            (100, 'shell', {'id': 1, 'action': 'nope'}, 'bad_params'),
            (101, 'shell', {'id': 1, 'action': 'exec'}, 'bad_params'),
            (102, 'socks', {'action': 'nope'}, 'bad_params'),
            (103, 'socks', {'action': 'start', 'port': 'x'}, 'bad_params'),
            (104, 'bof.run', {'id': 1}, 'bad_params'),
            (105, 'assembly.run', {'id': 1, 'path': '/nope'}, 'bad_params'),
            (106, 'creds.reveal', {}, 'bad_params'),
            (107, 'ai.config.set', {}, 'bad_params'),
        ]
        for mid, method, params, want in cases:
            self.b.send({'id': mid, 'method': method, 'params': params})
            self.assertEqual(self.b.recv()['code'], want)

    def test_build_config_import(self):
        self.b.open()
        self.b.hello()
        self.b.send({'id': 110, 'method': 'build.config.import',
                     'params': {'path': '/nope.json'}})
        self.assertEqual(self.b.recv()['code'], 'bad_params')
        open('bad.json', 'w').write('{oops')
        self.b.send({'id': 111, 'method': 'build.config.import',
                     'params': {'path': os.path.abspath('bad.json')}})
        self.assertEqual(self.b.recv()['code'], 'bad_params')
        open('ok.json', 'w').write('{"target_os":"linux","_doc":"x"}')
        self.b.send({'id': 112, 'method': 'build.config.import',
                     'params': {'path': os.path.abspath('ok.json')}})
        r = self.b.recv()
        self.assertTrue(r['ok'])
        self.assertEqual(r['result']['target_os'], 'linux')
        self.assertNotIn('_doc', r['result'])

    def test_frame_cap(self):
        self.b.open()
        self.b.hello()
        self.b.sock.sendall(struct.pack('>I', 9 << 20))
        self.b.sock.close()


if __name__ == '__main__':
    unittest.main()
