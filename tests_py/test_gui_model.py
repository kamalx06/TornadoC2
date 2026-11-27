"""Beacon virtual model, selection, bulk bar, theme and state."""
import json
import os
import unittest

from support import TempState

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
try:
    from PySide6.QtWidgets import QApplication
    HAVE_QT = True
except Exception:  # pragma: no cover
    HAVE_QT = False

if HAVE_QT:
    from tornado_client.gui import GuiApp


def rows(n=3):
    return [{
        'id': 10 + i, 'display_name': f'h{i}', 'alias': '',
        'os': 'linux', 'arch': 'amd64', 'alive': True,
        'last_seen_age': 1, 'privilege': 'user', 'elevated': False,
        'viewers': [], 'fingerprint': 'f' * 32, 'checkins': 1,
        'last_addr': '1.1.1.1', 'sleep_interval': 5,
        'spawnto': '', 'integrity': 'medium',
        'parent_name': 'x',
    } for i in range(n)]


class TP:
    def post(self, *a, **k):
        return {}

    def close(self):
        pass


@unittest.skipUnless(HAVE_QT, 'PySide6 not installed')
class ModelTest(TempState):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        super().setUp()
        self.g = GuiApp({'name': 't', 'role': 'admin',
                         'server_host': 'x', 'server_port': 1}, TP())
        self.g.search_entry.setText('')

    def test_model_rows_and_cells(self):
        self.g._apply_beacon_rows(rows(3))
        self.assertEqual(self.g.beacon_model.rowCount(), 3)
        idx = self.g.beacon_model.index(0, 0)
        from PySide6.QtCore import Qt
        self.assertIn('10', self.g.beacon_model.data(
            idx, Qt.ItemDataRole.DisplayRole))
        tip = self.g.beacon_model.data(
            idx, Qt.ItemDataRole.ToolTipRole)
        self.assertIn('beacon #10', tip)

    def test_filter_keeps_model_small(self):
        self.g._apply_beacon_rows(rows(50))
        self.g.search_entry.setText('h4')
        self.g._on_search_change()
        self.assertGreater(self.g.beacon_model.rowCount(), 0)
        self.assertLess(self.g.beacon_model.rowCount(), 50)

    def test_multi_select_shows_bulk_bar(self):
        self.g._apply_beacon_rows(rows(3))
        sm = self.g.tree.selectionModel()
        from PySide6.QtCore import QItemSelectionModel
        sm.select(self.g.beacon_model.index(0, 0),
                  QItemSelectionModel.SelectionFlag.Select
                  | QItemSelectionModel.SelectionFlag.Rows)
        sm.select(self.g.beacon_model.index(1, 0),
                  QItemSelectionModel.SelectionFlag.Select
                  | QItemSelectionModel.SelectionFlag.Rows)
        self.assertFalse(self.g.bulk_bar.isHidden())
        self.assertEqual(sorted(self.g._selected_ids()),
                         ['10', '11'])

    def test_theme_toggle(self):
        self.g._toggle_light()
        self.assertIn('#f6f7f9', self.g.styleSheet())
        self.g._toggle_light()
        self.assertNotIn('#f6f7f9', self.g.styleSheet())

    def test_state_round_trip(self):
        self.g.search_entry.setText('abc')
        self.g._save_state()
        path = self.g._state_path()
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        data = json.load(open(path))
        self.assertEqual(data['filter'], 'abc')


if __name__ == '__main__':
    unittest.main()
