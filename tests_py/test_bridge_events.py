"""Bridge event poller mirrors server events to stderr."""
import contextlib
import io
import unittest
from unittest import mock

import support  # noqa: F401 - adds client/ to sys.path
from tornado_client import bridge


class StubSession:
    def __init__(self):
        self.calls = 0

    def get(self, path, params=None, timeout=10):
        self.calls += 1
        if self.calls == 1:
            return {'events': [
                {'seq': 1, 'level': 'info', 'text': 'first'},
                {'seq': 2, 'level': 'warn', 'text': 'second'},
            ], 'next': 2}
        bridge._EVENTS_GEN += 1
        return {'events': [], 'next': 2}


class EventStreamTest(unittest.TestCase):
    def setUp(self):
        self._old_session = bridge.SESSION
        self._old_gen = bridge._EVENTS_GEN
        bridge._EVENTS_GEN = 1
        self.session = StubSession()
        bridge.SESSION = self.session

    def tearDown(self):
        bridge.SESSION = self._old_session
        bridge._EVENTS_GEN = self._old_gen

    def test_stream_formats_and_tracks_since(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            bridge._event_stream(1)
        out = err.getvalue()
        self.assertIn('[srv:info] first', out)
        self.assertIn('[srv:warn] second', out)

    def test_m_events_forwards_params(self):
        seen = {}

        class S:
            def get(self, path, params, timeout=10):
                seen.update({'path': path, 'params': params})
                return {'events': [], 'next': 0}

        with mock.patch.object(bridge, 'SESSION', S()):
            bridge.m_events({'since': 3})
        self.assertEqual(seen['path'], '/api/v1/events')
        self.assertEqual(seen['params'], {'since': 3})

    def test_stop_bumps_generation(self):
        gen = bridge._EVENTS_GEN
        bridge._stop_event_stream()
        self.assertEqual(bridge._EVENTS_GEN, gen + 1)


if __name__ == '__main__':
    unittest.main()
