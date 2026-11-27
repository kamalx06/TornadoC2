"""Engagement tab behaviour: no churn, caps, worker exports."""
import os
import unittest

from support import TempState

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
try:
    from PySide6.QtWidgets import QApplication
    HAVE_QT = True
except Exception:  # pragma: no cover - depends on the venv
    HAVE_QT = False

if HAVE_QT:
    from tornado_client.gui import GuiApp


class FakeTransport:
    def __init__(self):
        self.calls = []

    def post(self, path, payload=None, **kw):
        self.calls.append((path, payload))
        return {}

    def close(self):
        pass


def payload(dataset, users=0):
    return {
        'schema': 2, 'dataset': dataset, 'hosts': [],
        'users': [{'user': f'u{i}', 'host': 'h'} for i in range(users)],
        'shares': [], 'services': [], 'evidence': [],
        'findings': [], 'timeline': [], 'mitre': [],
    }


@unittest.skipUnless(HAVE_QT, 'PySide6 not installed')
class EngagementTabTest(TempState):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        super().setUp()
        self.tp = FakeTransport()
        self.g = GuiApp({'name': 't', 'role': 'admin',
                         'server_host': 'x', 'server_port': 1}, self.tp)

    def test_same_dataset_does_not_rebuild(self):
        self.g._apply_engagement(payload('a', 3))
        first = self.g.model_tree.topLevelItem(0)
        self.g._apply_engagement(payload('a', 9))
        self.assertIs(self.g.model_tree.topLevelItem(0), first)
        self.assertEqual(first.text(0), 'user (3)')
        self.g._apply_engagement(payload('b', 9))
        self.assertEqual(self.g.model_tree.topLevelItem(0).text(0),
                         'user (9)')

    def test_group_cap(self):
        self.g._apply_engagement(payload('c', 250))
        parent = self.g.model_tree.topLevelItem(0)
        self.assertEqual(parent.childCount(), self.g.ENG_GROUP_CAP + 1)
        self.assertIn('50 more',
                      parent.child(parent.childCount() - 1).text(0))

    def test_export_goes_through_worker_queue(self):
        self.g._export = self.g._export  # attribute exists
        from PySide6.QtWidgets import QFileDialog
        out = os.path.join(self._tmp.name, 'iocs.csv')
        orig = QFileDialog.getSaveFileName
        QFileDialog.getSaveFileName = staticmethod(
            lambda *a, **k: (out, ''))
        captured = []
        self.g._command_q.put = lambda item: captured.append(item)
        try:
            self.g._export('ioc')
        finally:
            QFileDialog.getSaveFileName = orig
        self.assertEqual(captured and captured[0][0], 'callable')
        captured[0][1]()          # run the queued work inline
        self.assertTrue(os.path.exists(out))
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
