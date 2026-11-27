"""Graph model: privilege, parent and shared-attribute edges."""
import unittest

from support import TempState
from tornadoc2.beacon.graph import Graph


class Session:
    def __init__(self, sid, pid, ppid, priv, parent=None):
        self.id = sid
        self.pid = pid
        self.parent_id = parent
        self.identity = {
            'user': 'u', 'domain': 'D', 'privilege': priv,
            'elevated': priv != 'user', 'integrity': 'x',
            'pid': pid, 'parent_pid': ppid, 'machine_id': 'm',
            'parent_name': 'p', 'groups': [],
        }
        self.last_addr = '10.0.0.5'
        self.display_name = f'b{sid}'
        self.alive = True
        self.age = 1
        self.checkins = 1
        self.fingerprint = 'f'


class Engine:
    def __init__(self, rows):
        self.rows = rows

    def list_all(self):
        return self.rows


class GraphTest(TempState):
    def test_nodes_and_groups(self):
        g = Graph(Engine([Session(1, 10, 5, 'root'),
                          Session(2, 20, 10, 'admin')])).build()
        self.assertEqual(g['nodes'][0]['privilege'], 'root')
        self.assertEqual(g['groups']['privilege'],
                         {'root': [1], 'admin': [2]})
        shared = {s for e in g['edges'] for s in e['shared']}
        self.assertIn('process-parent', shared)

    def test_relay_parent(self):
        g = Graph(Engine([Session(1, 10, 0, 'root'),
                          Session(2, 20, 99, 'user', parent=1)])).build()
        self.assertTrue(any('relay-parent' in e['shared']
                            for e in g['edges']))
        self.assertEqual(Graph(Engine([])).find_path(1, 2), None)

    def test_path(self):
        e = Engine([Session(1, 10, 0, 'root'),
                    Session(2, 20, 10, 'user')])
        self.assertEqual(Graph(e).find_path(1, 2), [1, 2])


if __name__ == '__main__':
    unittest.main()
