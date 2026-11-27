"""Password-HMAC lockout (replaces TOTP as the online guess throttle)."""
import unittest

from support import TempState
from tornadoc2.team import server as srv


class LockoutTest(TempState):
    def tearDown(self):
        srv._auth_clear('alice')
        super().tearDown()

    def test_locks_after_threshold(self):
        for _ in range(srv.AUTH_MAX_FAILS - 1):
            self.assertFalse(srv._auth_fail('alice'))
        self.assertTrue(srv._auth_fail('alice'))
        self.assertTrue(srv._auth_locked('alice'))

    def test_clear_resets(self):
        srv._auth_fail('alice')
        srv._auth_clear('alice')
        self.assertFalse(srv._auth_locked('alice'))

    def test_expiry(self):
        old = srv.AUTH_LOCK_SECONDS
        srv.AUTH_LOCK_SECONDS = 0
        try:
            for _ in range(srv.AUTH_MAX_FAILS):
                srv._auth_fail('alice')
            self.assertFalse(srv._auth_locked('alice'))
        finally:
            srv.AUTH_LOCK_SECONDS = old


if __name__ == '__main__':
    unittest.main()
