#!/usr/bin/env python3
"""Headless GUI benchmark: 10k rows render and scroll.

Run with QT_QPA_PLATFORM=offscreen. Exits non-zero when a budget is
missed, so CI can gate on it.
"""
import os
import sys
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..',
                                'client'))

from PySide6.QtWidgets import QApplication  # noqa: E402

from tornado_client.gui import GuiApp  # noqa: E402

RENDER_BUDGET_MS = 1500
REPEAT_BUDGET_MS = 250


class TP:
    def post(self, *a, **k):
        return {}

    def close(self):
        pass


def rows(n):
    return [{
        'id': 1000 + i, 'display_name': f'host{i:05d}',
        'alias': '', 'os': 'windows', 'arch': 'amd64',
        'alive': i % 3 != 0, 'last_seen_age': i % 600,
        'privilege': 'user', 'elevated': False, 'viewers': [],
        'fingerprint': 'f' * 32, 'checkins': 1, 'last_addr': '10.0.0.1',
        'sleep_interval': 5, 'spawnto': '', 'integrity': 'medium',
        'parent_name': 'explorer.exe',
    } for i in range(n)]


def main() -> int:
    app = QApplication.instance() or QApplication([])
    g = GuiApp({'name': 'bench', 'role': 'admin',
                'server_host': 'x', 'server_port': 1}, TP())

    # A restored filter would skew the numbers.
    g._filter_text = ''
    g.search_entry.setText('')

    data = rows(10000)
    t0 = time.perf_counter()
    g._apply_beacon_rows(data)
    app.processEvents()
    first = (time.perf_counter() - t0) * 1000
    n = g.beacon_model.rowCount()
    if n != 10000:
        sys.__stdout__.write(f'FAIL: rowCount {n}\n')
        return 1

    t0 = time.perf_counter()
    for _ in range(5):
        g._render_beacon_tree()
        app.processEvents()
    repeat = (time.perf_counter() - t0) * 1000 / 5

    t0 = time.perf_counter()
    for _ in range(20):
        g.tree.scrollToBottom()
        g.tree.scrollToTop()
        app.processEvents()
    scroll = (time.perf_counter() - t0) * 1000 / 40

    out = sys.__stdout__
    out.write(f'render_10k_ms={first:.1f} repeat_ms={repeat:.1f} '
              f'scroll_frame_ms={scroll:.1f}\n')
    out.flush()
    bad = []
    if first > RENDER_BUDGET_MS:
        bad.append(f'render {first:.0f} > {RENDER_BUDGET_MS}')
    if repeat > REPEAT_BUDGET_MS:
        bad.append(f'repeat {repeat:.0f} > {REPEAT_BUDGET_MS}')
    if bad:
        sys.__stdout__.write('FAIL: ' + ', '.join(bad) + '\n')
        return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc(file=sys.__stderr__)
        sys.exit(2)
