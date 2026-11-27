"""Armory: locked source, manifest parsing, install/update/remove."""
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import TempState
from tornado_client import armory


def _bof(name='ok', body=b'MZ' + b'x' * 40):
    return body


class Fixture:
    def __init__(self):
        self.files = {}
        self.metas = {}
        self.rows = []
        self.add('ok', b'MZ' + b'x' * 40, '1.0.0')

    def add(self, name, body, version='1.0.0', desc='test'):
        sha = hashlib.sha256(body).hexdigest()
        rel = f'bofs/{name}/{name}.o'
        self.files[rel] = body
        self.rows = [r for r in self.rows if r['name'] != name]
        self.rows.append({
            'name': name, 'format': 'coff-x64', 'description': desc,
            'version': version, 'file': f'{name}.o',
            'sha256': sha, 'size': len(body), 'path': rel,
        })
        self.metas[f'bofs/{name}/meta.json'] = json.dumps(
            self.rows[-1]).encode()

    def sync_meta(self, name='ok'):
        row = next(r for r in self.rows if r['name'] == name)
        self.metas[f'bofs/{name}/meta.json'] = json.dumps(
            row).encode()

    def manifest(self):
        return json.dumps({'version': 2, 'extensions': self.rows}).encode()

    def archive(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tf:
            for rel, body in [
                    ('index.json', self.manifest()),
                    *self.files.items(), *self.metas.items()]:
                info = tarfile.TarInfo(rel)
                info.size = len(body)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(body))
            link = tarfile.TarInfo('bofs/ok/link.o')
            link.type = tarfile.SYMTYPE
            link.linkname = '../../outside.o'
            tf.addfile(link)
            dev = tarfile.TarInfo('bofs/ok/dev')
            dev.type = tarfile.CHRTYPE
            tf.addfile(dev)
        return buf.getvalue()

    def fetch(self, url, cap, timeout):
        if url == armory.ARMORY_ARCHIVE_URL:
            return self.archive()
        if url == armory.ARMORY_MANIFEST_URL:
            return self.manifest()
        prefix = armory.ARMORY_RAW_BASE + '/'
        if url.startswith(prefix):
            rel = url[len(prefix):]
            if rel in self.files:
                return self.files[rel]
            raise armory.ArmoryError(f'404 {rel}')
        raise armory.ArmoryError(f'unexpected URL {url}')


class ArmoryTest(TempState):
    def setUp(self):
        super().setUp()
        from tornadoc2_mcp import paths
        self._old_paths = (paths.STATE_DIR, paths.ARMORY_DIR, paths.PINS_DIR)
        paths.STATE_DIR = Path(self._tmp.name) / 'state'
        paths.ARMORY_DIR = paths.STATE_DIR / 'armory'
        paths.PINS_DIR = paths.STATE_DIR / 'pins'
        self.fx = Fixture()
        self.patch = mock.patch.object(
            armory, '_read_url', side_effect=self.fx.fetch)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        from tornadoc2_mcp import paths
        paths.STATE_DIR, paths.ARMORY_DIR, paths.PINS_DIR = self._old_paths
        super().tearDown()

    def test_source_is_locked_constant(self):
        self.assertEqual(armory.ARMORY_REPO,
                         'https://github.com/kamalx06/tornadoc2-armory')
        cat = armory.catalogue(refresh=True)
        self.assertEqual(cat['repo'], armory.ARMORY_REPO)
        self.assertEqual(cat['branch'], 'main')

    def test_list_without_url_argument(self):
        cat = armory.catalogue(refresh=True)
        self.assertEqual([r['name'] for r in cat['extensions']], ['ok'])

    def test_install_lookup_uninstall(self):
        armory.catalogue(refresh=True)
        r = armory.install(['ok'])
        self.assertEqual(r['done'], [{'name': 'ok'}])
        got = armory.lookup('ok')
        self.assertEqual(got[0], self.fx.files['bofs/ok/ok.o'])
        self.assertEqual(got[1], 'coff-x64')
        self.assertIn('ok', armory.installed())
        self.assertEqual(armory.remove(['ok'])['done'], ['ok'])
        self.assertIsNone(armory.lookup('ok'))

    def test_cna_is_stored(self):
        self.fx.files['bofs/ok/script.cna'] = b'beacon_command_register("x");'
        self.fx.rows[0]['cna'] = 'script.cna'
        self.fx.sync_meta()
        armory.catalogue(refresh=True)
        armory.install(['ok'])
        path = os.path.join(armory.state_dir(), 'installed', 'ok',
                            'script.cna')
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_install_is_0600_and_dir_0700(self):
        armory.catalogue(refresh=True)
        armory.install(['ok'])
        base = Path(armory.state_dir()) / 'installed' / 'ok'
        self.assertEqual(os.stat(base).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(base / 'ok.o').st_mode & 0o777, 0o600)

    def test_digest_mismatch_fails(self):
        self.fx.rows[0]['sha256'] = '0' * 64
        armory.catalogue(refresh=True)
        r = armory.install(['ok'])
        self.assertEqual(r['done'], [])
        self.assertIn('sha256 mismatch', r['failed'][0]['error'])
        self.assertNotIn('ok', armory.installed())

    def test_already_installed_skips_without_replace(self):
        armory.catalogue(refresh=True)
        armory.install(['ok'])
        r = armory.install(['ok'])
        self.assertTrue(r['done'][0]['skipped'])
        r = armory.install(['ok'], replace=True)
        self.assertEqual(r['done'], [{'name': 'ok'}])

    def test_update_detects_new_version(self):
        armory.catalogue(refresh=True)
        armory.install(['ok'])
        self.fx.add('ok', b'MZ' + b'y' * 60, '2.0.0')
        r = armory.update(['ok'])
        self.assertEqual(r['done'], [{'name': 'ok'}])
        at = armory.installed()['ok']
        self.assertEqual(at['version'], '2.0.0')
        self.assertEqual(at['sha256'],
                         hashlib.sha256(b'MZ' + b'y' * 60).hexdigest())

    def test_update_skips_same_version(self):
        armory.catalogue(refresh=True)
        armory.install(['ok'])
        r = armory.update(all_names=True)
        self.assertEqual(r['skipped'], [{'name': 'ok'}])

    def test_traversal_path_is_refused(self):
        self.fx.rows[0]['path'] = '../outside.o'
        self.fx.sync_meta()
        with self.assertRaises(armory.ArmoryError):
            armory.catalogue(refresh=True)

    def test_unsupported_format_fails(self):
        self.fx.rows[0]['format'] = 'exe'
        self.fx.sync_meta()
        with self.assertRaises(armory.ArmoryError):
            armory.catalogue(refresh=True)

    def test_archive_falls_back_to_manifest(self):
        with mock.patch.object(
                armory, 'ARMORY_ARCHIVE_URL',
                'https://codeload.github.com/nope.tar.gz'):
            cat = armory.catalogue(refresh=True)
        self.assertEqual([r['name'] for r in cat['extensions']], ['ok'])

    def test_offline_refresh_uses_cache(self):
        armory.catalogue(refresh=True)
        with mock.patch.object(
                armory, '_read_url',
                side_effect=armory.ArmoryError('offline')):
            cat = armory.catalogue(refresh=True)
        self.assertTrue(cat['stale'])
        self.assertIn('offline', cat['error'])

    def test_archive_symlink_and_device_are_ignored(self):
        cat = armory.catalogue(refresh=True)
        self.assertEqual([r['name'] for r in cat['extensions']], ['ok'])
        armory.install(['ok'])
        self.assertFalse(os.path.exists(
            os.path.join(armory.state_dir(), 'installed', 'ok',
                         'link.o')))

    def test_rel_rejects_tricks(self):
        for bad in ('/abs.o', '../x.o', 'bofs/../x.o', 'bofs\\\\x.o',
                    ''):
            with self.assertRaises(armory.ArmoryError):
                armory._rel(bad)
        self.assertEqual(armory._rel('bofs/ok/ok.o'), 'bofs/ok/ok.o')

    def test_redirect_outside_allowlist_is_refused(self):
        handler = armory._Redirect()
        with self.assertRaises(armory.ArmoryError):
            handler.redirect_request(
                None, None, 302, '', {}, 'https://evil.example/x')

    def test_unknown_name(self):
        armory.catalogue(refresh=True)
        r = armory.install(['nope'])
        self.assertIn('not in armory', r['failed'][0]['error'])


if __name__ == '__main__':
    unittest.main()
