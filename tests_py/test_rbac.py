"""RBAC and command-catalogue invariants."""
import unittest

from support import TempState
from tornadoc2.team import commands, constants


class CapabilityMatrix(TempState):
    ROLES = ('operator', 'admin', 'local', 'viewer', 'guardian')

    def test_listener_caps(self):
        for role in ('operator', 'admin', 'local'):
            for cap in ('listener.view', 'listener.manage',
                        'listener.delete'):
                self.assertTrue(constants.has_capability(
                    role, cap, is_local=False), (role, cap))
        for role in ('viewer', 'guardian'):
            self.assertFalse(constants.has_capability(
                role, 'listener.view', is_local=False), role)

    def test_armory_caps(self):
        for role in ('operator', 'admin', 'local'):
            self.assertTrue(constants.has_capability(
                role, 'armory.view', is_local=False))
        for role in ('viewer', 'guardian'):
            self.assertFalse(constants.has_capability(
                role, 'armory.view', is_local=False))

    def test_help_filtering(self):
        for role in self.ROLES:
            caps = frozenset(
                constants.ROLE_CAPABILITIES.get(role, frozenset()))
            main = [c['name'] for c in
                    commands.filter_for(role, caps, None)['main']]
            self.assertEqual('listeners' in main,
                             role in ('operator', 'admin', 'local'))
            self.assertEqual('armory' in main, 'armory.view' in caps)

    def test_leaked_aliases(self):
        for role in ('viewer', 'guardian'):
            caps = frozenset(
                constants.ROLE_CAPABILITIES.get(role, frozenset()))
            main = [c['name'] for c in
                    commands.filter_for(role, caps, None)['main']]
            self.assertNotIn('listener', main)
            self.assertNotIn('arm', main)


if __name__ == '__main__':
    unittest.main()
