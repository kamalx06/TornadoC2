"""At-rest encryption round trips, migration and key handling."""
import json
import os
import unittest

from support import TempState
from tornadoc2.team import atrest
from tornadoc2.team.creds import CredStore
from tornadoc2.team.aliases import AliasStore
from tornadoc2.team.chat import ChatRoom
from tornadoc2.team.engagement import Engagement


class AtRestTest(TempState):
    def tearDown(self):
        os.environ.pop('TORNADOC2_AT_REST', None)
        os.environ.pop('TORNADOC2_AT_REST_KEY', None)
        atrest.reset_cache()
        super().tearDown()

    def test_round_trip_and_magic(self):
        atrest.save_json('a.json', {'x': 1})
        raw = open('a.json', 'rb').read()
        self.assertTrue(raw.startswith(b'T2ENC2\n'))
        self.assertEqual(atrest.load_json('a.json', {}), {'x': 1})
        self.assertEqual(os.stat('a.json').st_mode & 0o777, 0o600)

    def test_key_created_0600(self):
        atrest.key()
        st = os.stat('logs/at_rest.key')
        self.assertEqual(st.st_mode & 0o777, 0o600)
        self.assertEqual(st.st_size, 32)

    def test_plaintext_still_read(self):
        open('b.json', 'w').write(json.dumps({'y': 2}))
        self.assertEqual(atrest.load_json('b.json', {}), {'y': 2})
        self.assertFalse(atrest.is_encrypted('b.json'))
        self.assertTrue(atrest.migrate('b.json'))
        self.assertTrue(atrest.is_encrypted('b.json'))
        self.assertEqual(atrest.load_json('b.json', {}), {'y': 2})

    def test_swapped_files_fail(self):
        atrest.save_json('a.json', {'who': 'a'})
        atrest.save_json('b.json', {'who': 'b'})
        raw = open('a.json', 'rb').read()
        open('b.json', 'wb').write(raw)
        with self.assertRaises(Exception):
            atrest.load_json('b.json', {})

    def test_v1_blob_still_readable(self):
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = b'0' * 12
        blob = AESGCM(atrest.key()).encrypt(
            nonce, b'{"old": 1}', b'tornadoc2/atrest/v1')
        open('old.json', 'wb').write(
            b'T2ENC1\n' + base64.b64encode(nonce + blob))
        self.assertEqual(atrest.load_json('old.json', {}), {'old': 1})

    def test_v1_wrong_key_is_atrest_error(self):
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = b'1' * 12
        blob = AESGCM(b'k' * 32).encrypt(nonce, b'{}',
                                         b'tornadoc2/atrest/v1')
        open('bad.json', 'wb').write(
            b'T2ENC1\n' + base64.b64encode(nonce + blob))
        with self.assertRaises(atrest.AtRestError):
            atrest.load_json('bad.json', {})

    def test_disabled(self):
        os.environ['TORNADOC2_AT_REST'] = 'off'
        atrest.save_json('c.json', {'z': 3})
        self.assertFalse(open('c.json', 'rb').read()
                         .startswith(b'T2ENC1'))
        self.assertEqual(atrest.load_json('c.json', {}), {'z': 3})

    def test_env_key(self):
        atrest.reset_cache()
        os.environ['TORNADOC2_AT_REST_KEY'] = (
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
        atrest.save_json('d.json', {'k': 1})
        atrest.reset_cache()
        self.assertEqual(atrest.load_json('d.json', {}), {'k': 1})

    def test_creds_and_engagement_are_encrypted(self):
        c = CredStore('logs/creds.json')
        c.add(user='u', domain='d', kind='plaintext', value='p',
              source_beacon=1, source_path='', found_by='x')
        self.assertTrue(atrest.is_encrypted('logs/creds.json'))
        self.assertNotIn(b'plaintext', open('logs/creds.json', 'rb').read())
        self.assertEqual(len(CredStore('logs/creds.json').list()), 1)
        e = Engagement('logs/engagement.json')
        e.add_finding('t', 'low', 'h', 'd', 'x')
        self.assertTrue(atrest.is_encrypted('logs/engagement.json'))


class MoreStoresTest(TempState):
    def test_aliases_webhooks_scheduler(self):
        from tornadoc2.team.webhooks import WebhookStore
        a = AliasStore('logs/aliases.json')
        a.set_alias(1, 'box', 'alice')
        self.assertTrue(atrest.is_encrypted('logs/aliases.json'))
        self.assertEqual(AliasStore('logs/aliases.json').get(1)['alias'],
                         'box')
        import socket
        old = socket.getaddrinfo
        socket.getaddrinfo = lambda *a, **k: [
            (2, 1, 6, '', ('93.184.216.34', 443))]
        try:
            w = WebhookStore('logs/webhooks.json')
            w.add(name='h', kind='slack', url='https://x',
                  events=['new-beacon'], added_by='alice')
        finally:
            socket.getaddrinfo = old
        self.assertTrue(atrest.is_encrypted('logs/webhooks.json'))
        self.assertEqual(len(WebhookStore('logs/webhooks.json').list()),
                         1)

    def test_chat_migration(self):
        import json as _j
        from tornadoc2.team.chat import migrate_persisted
        os.makedirs('logs/chat', exist_ok=True)
        msg = {'id': 1, 'operator': 'a', 'text': 'legacy',
               'ts': 1.0, 'kind': 'chat'}
        open('logs/chat/chat.jsonl', 'w').write(_j.dumps(msg) + '\n')
        open('logs/chat/chat.txt', 'w').write('legacy line\n')
        self.assertEqual(migrate_persisted('logs/chat'), 2)
        self.assertTrue(open('logs/chat/chat.jsonl').read()
                        .startswith('E1:'))
        self.assertEqual(ChatRoom('logs/chat').history(5)[0]['text'],
                         'legacy')

    def test_chat_bodies_and_meta_encrypted(self):
        r = ChatRoom('logs/chat')
        m = r.post('alice', 'admin', 'top secret', source_ip='1')
        path = os.path.join('logs/chat/chat.jsonl')
        self.assertTrue(open(path).read().startswith('E1:'))
        r2 = ChatRoom('logs/chat')
        self.assertEqual(r2.history(10)[0]['text'], 'top secret')
        buf = m.get('id')
        self.assertTrue(buf)


if __name__ == '__main__':
    unittest.main()
