"""Server event ring: capacity, filtering, redaction and waiting."""
import threading
import time
import unittest

from tornadoc2.team.events import EventRing


class EventRingTest(unittest.TestCase):
    def setUp(self):
        self.ring = EventRing(capacity=5)

    def test_capacity_is_bounded(self):
        for i in range(20):
            self.ring.emit('info', 'system', f'e{i}')
        rows, nxt = self.ring.read(0, 50, cn='alice', ip='1.1.1.1',
                                   all_scope=True)
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[-1]['text'], 'e19')
        self.assertEqual(nxt, 20)

    def test_sequences_are_monotonic(self):
        a = self.ring.emit('info', 'system', 'a')
        b = self.ring.emit('warn', 'system', 'b')
        self.assertLess(a.seq, b.seq)
        _, nxt = self.ring.read(a.seq, 10, cn='alice', all_scope=True)
        self.assertEqual(nxt, b.seq)

    def test_newlines_and_length_are_normalized(self):
        event = self.ring.emit('info', 'system', 'a\nb' + 'x' * 900)
        self.assertNotIn('\n', event.text)
        self.assertEqual(len(event.text), 500)

    def test_own_scope_hides_other_operators(self):
        self.ring.emit('info', 'system', 'mine', cn='alice',
                       ip='1.1.1.1')
        self.ring.emit('info', 'system', 'theirs', cn='bob',
                       ip='2.2.2.2')
        self.ring.emit('warn', 'auth', 'preauth', ip='1.1.1.1')
        rows, _ = self.ring.read(0, 50, cn='alice', ip='1.1.1.1')
        self.assertEqual([r['text'] for r in rows],
                         ['mine', 'preauth'])

    def test_all_scope_sees_everything(self):
        self.ring.emit('info', 'system', 'mine', cn='alice')
        self.ring.emit('info', 'system', 'theirs', cn='bob')
        rows, _ = self.ring.read(0, 50, cn='alice', all_scope=True)
        self.assertEqual(len(rows), 2)

    def test_http_record_classifies_and_skips_poll(self):
        self.ring.record_http('POST', '/api/v1/beacons', 200, 4, 10,
                              cn='alice', ip='1.1.1.1')
        self.ring.record_http('POST', '/api/v1/events', 200, 1, 2,
                              cn='alice', ip='1.1.1.1')
        self.ring.record_http('POST', '/api/v1/nope', '404', 2, 3,
                              cn='alice', ip='1.1.1.1')
        rows, _ = self.ring.read(0, 50, cn='alice')
        self.assertEqual([r['level'] for r in rows], ['info', 'warn'])
        self.assertEqual(rows[0]['meta']['status'], 200)

    def test_http_record_accepts_handler_dict(self):
        self.ring.record_http({
            'method': 'POST', 'path': '/api/v1/x', 'status': '200',
            'duration_ms': 3, 'size': 4, 'cn': 'alice',
            'ip': '1.1.1.1', 'ua': 'UA',
        })
        rows, _ = self.ring.read(0, 10, cn='alice')
        self.assertEqual(rows[0]['meta']['method'], 'POST')
        self.assertEqual(rows[0]['meta']['ua'], 'UA')

    def test_500_is_error(self):
        self.ring.record_http('POST', '/x', 500, 1, 0, cn='alice')
        rows, _ = self.ring.read(0, 10, cn='alice')
        self.assertEqual(rows[0]['level'], 'err')

    def test_wait_wakes_on_emit(self):
        saw = []

        def waiter():
            self.ring.wait(0, 2.0)
            saw.append(self.ring.latest())

        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.05)
        self.ring.emit('info', 'system', 'wake')
        t.join(2)
        self.assertEqual(saw, [1])

    def test_wait_times_out(self):
        started = time.monotonic()
        self.ring.wait(0, 0.05)
        self.assertGreaterEqual(time.monotonic() - started, 0.04)


if __name__ == '__main__':
    unittest.main()
