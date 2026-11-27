"""Listener manager validation, persistence and conflict rules."""
import json
import os
import socket
import tempfile
import unittest

from support import ROOT, TempState, free_port
from tornadoc2.team import atrest
from tornadoc2.beacon.listener_manager import (
    ListenerConflict, ListenerInvalid, ListenerManager,
)

TLS = {'mode': 'server', 'cert_path': ROOT + '/tls_certs/server.pem',
       'key_path': ROOT + '/tls_certs/server.key'}


class Engine:
    def list_all(self):
        return []

    def get(self, _sid):
        return None


class Handler:
    beacon = Engine()
    colors = {'cyan': '', 'yellow': '', 'red': '', 'end': ''}
    certfile = ROOT + '/tls_certs/server.pem'
    keyfile = ROOT + '/tls_certs/server.key'
    mtls_ca_cert = ROOT + '/mtls_certs/ca.pem'


def spec(port=None, **kw):
    base = {'type': 'http', 'name': 'a', 'host': '127.0.0.1',
            'port': port or free_port(), 'tls': TLS, 'enabled': True}
    base.update(kw)
    return base


class ManagerTest(TempState):
    def setUp(self):
        super().setUp()
        self.port = free_port()
        self.store = os.path.join(os.getcwd(), 'listeners.json')
        self.m = ListenerManager(Handler(), store_path=self.store)

    def test_store_created_0600(self):
        self.assertTrue(os.path.isfile(self.store))
        self.assertEqual(os.stat(self.store).st_mode & 0o777, 0o600)
        self.assertEqual(atrest.load_json(self.store, {})['listeners'], [])

    def test_name_and_type_validation(self):
        with self.assertRaises(ListenerInvalid):
            self.m.create(spec(type='bogus'), by='t')
        with self.assertRaises(ListenerInvalid):
            self.m.create(spec(name='bad name'), by='t')
        with self.assertRaises(ListenerInvalid):
            self.m.create(spec(port=70000), by='t')

    def test_tls_outside_root_rejected(self):
        with self.assertRaises(ListenerInvalid):
            self.m.create(spec(tls={'mode': 'server',
                                    'cert_path': '/etc/hostname',
                                    'key_path': '/etc/hostname'}), by='t')

    def test_tls_none_normalized(self):
        c = self.m.create(spec(tls={'mode': 'none'}), by='t')
        self.assertEqual(c['tls']['mode'], 'server')
        self.assertIn('cert_path', c['tls'])

    def test_conflict_and_port_release(self):
        a = self.m.create(spec(self.port), by='t')
        self.assertEqual(self.m.start(a['id'], by='t')['status'], 'running')
        with self.assertRaises(ListenerConflict) as ctx:
            self.m.create(spec(self.port, name='b'), by='t')
        self.assertIn(a['id'], str(ctx.exception))
        self.m.stop(a['id'], by='t')
        s = socket.socket()
        s.bind(('127.0.0.1', self.port))
        s.close()
        self.m.create(spec(self.port, name='b'), by='t')

    def test_delete_running_refused(self):
        a = self.m.create(spec(self.port), by='t')
        self.m.start(a['id'], by='t')
        from tornadoc2.beacon.listener_manager import ListenerStateError
        with self.assertRaises(ListenerStateError):
            self.m.delete(a['id'], by='t')
        self.m.stop(a['id'], by='t')
        self.m.delete(a['id'], by='t')

    def test_unique_ids(self):
        ids = {self.m.create(spec(free_port(), name=str(i)), by='t')['id']
               for i in range(10)}
        self.assertEqual(len(ids), 10)
        self.assertTrue(all(x.startswith('lst_') for x in ids))


if __name__ == '__main__':
    unittest.main()
