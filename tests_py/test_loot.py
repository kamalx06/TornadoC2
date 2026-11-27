"""Loot store: at-rest encryption, chunked path and dedup."""
import os
import unittest

from support import TempState
from tornadoc2.team import atrest
from tornadoc2.team.lootstore import LootStore


class LootTest(TempState):
    def setUp(self):
        super().setUp()
        self.s = LootStore('loot')

    def put(self, data, name='a.bin'):
        return self.s.store(data, uploaded_by='alice',
                            display_name=name)

    def test_round_trip_encrypted(self):
        data = b'secret bytes' * 100
        r = self.put(data)
        path = os.path.join('loot', r['sha256'])
        self.assertTrue(open(path, 'rb').read().startswith(b'T2ENC2\n'))
        self.assertTrue(atrest.is_encrypted(path + '.meta'))
        self.assertEqual(self.s.read(r['sha256']), data)

    def test_large_blob_stored_plain(self):
        self.s.MAX_ENCRYPT_BYTES = 8
        data = b'x' * 1024
        r = self.put(data)
        path = os.path.join('loot', r['sha256'])
        self.assertFalse(open(path, 'rb').read().startswith(b'T2ENC1'))
        self.assertEqual(self.s.read(r['sha256']), data)

    def test_dedup_keeps_owner(self):
        data = b'dup'
        a = self.put(data)
        b = self.put(data, name='b.bin')
        self.assertTrue(b['deduped'])
        self.assertEqual(a['sha256'], b['sha256'])
        self.assertEqual(self.s.stat(a['sha256'])['owner'], 'alice')

    def test_chunked_upload_encrypts(self):
        data = os.urandom(2048)
        import hashlib
        digest = hashlib.sha256(data).hexdigest()
        up = self.s.initiate_upload('alice', len(data), digest,
                                    'c.bin')
        self.s.append_chunk(up['upload_id'], 0, data)
        self.s.finish_upload(up['upload_id'])
        self.assertEqual(self.s.read(digest), data)
        self.assertTrue(atrest.is_encrypted(
            os.path.join('loot', digest)))


if __name__ == '__main__':
    unittest.main()
