"""Request handler routes log_request to the sink instead of stdout."""
import unittest

from tornadoc2.quiet_werkzeug import (
    QuietWSGIRequestHandler, make_request_handler,
)


class DummyHeaders:
    def get(self, key, default=''):
        return 'UA/1' if key == 'User-Agent' else default


class DummyConn:
    def getpeercert(self):
        return {'subject': ((('commonName', 'alice'),),)}


class Dummy:
    command = 'POST'
    path = '/api/v1/beacons?x=1'
    headers = DummyHeaders()
    connection = DummyConn()
    client_address = ('1.1.1.1', 4444)
    _t2_started = 1.0

    def _peer_cn(self):
        return 'alice'


class SinkTest(unittest.TestCase):
    def test_factory_binds_sink_and_emits_record(self):
        seen = []
        cls = make_request_handler(lambda rec: seen.append(rec))
        self.assertTrue(issubclass(cls, QuietWSGIRequestHandler))
        dummy = Dummy()
        dummy.log_sink = cls.log_sink
        cls.log_request(dummy, '201', '42')
        self.assertEqual(seen[0]['method'], 'POST')
        self.assertEqual(seen[0]['path'], '/api/v1/beacons')
        self.assertEqual(seen[0]['status'], '201')
        self.assertEqual(seen[0]['cn'], 'alice')
        self.assertEqual(seen[0]['ip'], '1.1.1.1')

    def test_sink_failure_never_raises(self):
        def boom(_rec):
            raise RuntimeError('sink down')
        cls = make_request_handler(boom)
        cls.log_request(Dummy(), '200', '1')

    def test_no_sink_is_silent(self):
        QuietWSGIRequestHandler.log_request(Dummy(), '200', '1')


if __name__ == '__main__':
    unittest.main()
