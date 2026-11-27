"""Shared build spec: descriptors, normalization and every rule."""
import unittest

import support  # noqa: F401 - adds client/ to sys.path
from tornado_client import bridge
from tornadoc2.beacon import build_spec


def fields(spec):
    return {e['field'] for e in build_spec.validate(spec)}


class ValidateTest(unittest.TestCase):
    def base(self, **kw):
        spec = {
            'target_os': 'linux', 'target_arch': 'amd64',
            'output_format': 'elf', 'transport_mode': 'http',
            'url': 'https://c2.example:443',
        }
        spec.update(kw)
        return spec

    def test_minimal_http_is_valid(self):
        self.assertEqual(build_spec.validate(self.base()), [])

    def test_unknown_transport(self):
        self.assertIn('transport_mode', fields(
            self.base(transport_mode='smtp')))

    def test_exclusive_transport_cannot_combine(self):
        self.assertIn('transport_mode', fields(
            self.base(transport_mode='http,smb', smb_pipe='p')))

    def test_smb_requires_windows(self):
        self.assertIn('target_os', fields(
            self.base(transport_mode='smb', smb_pipe='p')))

    def test_smb_requires_pipe(self):
        self.assertIn('smb_pipe', fields(self.base(
            target_os='windows', output_format='exe',
            transport_mode='smb')))

    def test_unc_pipe_needs_pipe_segment(self):
        self.assertIn('smb_pipe', fields(self.base(
            target_os='windows', output_format='exe',
            transport_mode='smb', smb_pipe=r'\\HOST\\name')))

    def test_tcp_token_must_be_hex64(self):
        self.assertIn('tcp_bind_token', fields(self.base(
            transport_mode='tcp', tcp_bind_addr='0.0.0.0:4444',
            tcp_bind_token='abc', pivot_key_path='mtls_certs/pivot.pem')))

    def test_pivot_requires_key(self):
        self.assertIn('pivot_key_path', fields(self.base(
            transport_mode='tcp', tcp_bind_addr='0.0.0.0:4444',
            tcp_bind_token='a' * 64)))

    def test_child_cannot_be_parent(self):
        self.assertIn('transport_mode', fields(self.base(
            transport_mode='smb', target_os='windows',
            output_format='exe', smb_pipe='p',
            smb_relay_pipe='relay', pivot_key_path='/x')))

    def test_stager_rules(self):
        got = fields(self.base(
            output_format='stager', url='http://x', stage_name=''))
        self.assertTrue({'url', 'stage_name'} <= got)
        self.assertIn('sleep_mask', fields(self.base(
            output_format='stager', url='https://x',
            stage_name='full', sleep_mask='cronos')))

    def test_icmp_linux_only_and_ipv4(self):
        self.assertIn('target_os', fields(self.base(
            target_os='windows', output_format='exe',
            transport_mode='icmp', icmp_host='1.2.3.4')))
        self.assertIn('icmp_host', fields(self.base(
            transport_mode='icmp', icmp_host='nope')))

    def test_wireguard_required_fields(self):
        got = fields(self.base(transport_mode='wireguard'))
        self.assertTrue({
            'wireguard_server_pubkey', 'wireguard_server_addr',
            'wireguard_agent_privkey', 'wireguard_tunnel_ip'} <= got)

    def test_wireguard_addr_needs_port(self):
        self.assertIn('wireguard_server_addr', fields(self.base(
            transport_mode='wireguard',
            wireguard_server_pubkey='k',
            wireguard_server_addr='host',
            wireguard_agent_privkey='k',
            wireguard_tunnel_ip='10.99.0.2')))

    def test_websocket_blocks_dll(self):
        self.assertIn('output_format', fields(self.base(
            target_os='windows', output_format='dll',
            transport_mode='websocket', url='https://x')))

    def test_dns_requires_zone(self):
        self.assertIn('dns_domain', fields(self.base(
            transport_mode='dns')))

    def test_doh_requires_https_resolver(self):
        self.assertIn('doh_resolver', fields(self.base(
            transport_mode='doh', dns_domain='c2.example',
            doh_resolver='http://x')))

    def test_sleep_mask_os_and_arch(self):
        self.assertIn('sleep_mask', fields(self.base(
            sleep_mask='cronos')))
        self.assertIn('sleep_mask', fields(self.base(
            target_os='windows', output_format='exe',
            target_arch='arm64', sleep_mask='hwbp')))

    def test_indirect_windows_only(self):
        self.assertIn('syscall_method', fields(self.base(
            syscall_method='indirect')))

    def test_apc_requirements(self):
        self.assertIn('inject_method', fields(self.base(
            inject_method='apc')))
        self.assertNotIn('inject_method', fields(self.base(
            target_os='windows', output_format='exe',
            inject=True, inject_method='apc')))

    def test_inject_format(self):
        self.assertIn('output_format', fields(self.base(
            target_os='windows', output_format='dll', inject=True)))

    def test_jump_and_persistence_lists(self):
        self.assertIn('jump_methods', fields(
            self.base(jump_methods='psexec,bogus')))
        self.assertIn('persistence', fields(
            self.base(persistence='cron,bogus')))

    def test_bad_formats_platform(self):
        self.assertIn('output_format', fields(self.base(
            output_format='exe')))
        self.assertIn('output_format', fields(self.base(
            target_os='windows', output_format='elf')))

    def test_remote_profile_must_be_a_name(self):
        self.assertIn('c2_profile', {
            e['field'] for e in build_spec.validate(
                self.base(c2_profile='../x'), remote=True)})

    def test_normalize_fills_defaults(self):
        spec = build_spec.normalize({'transport_mode': 'http,dns'})
        self.assertEqual(spec['target_os'], 'linux')
        self.assertEqual(spec['output_format'], 'elf')
        self.assertEqual(spec['transport_failover_after'], 3)
        self.assertEqual(spec['transport_mode'], 'http,dns')

    def test_descriptor_is_complete(self):
        desc = build_spec.descriptor()
        ids = [t['id'] for t in desc['transports']]
        self.assertEqual(set(ids), set(build_spec.MODES))
        self.assertIn('url', [f['name'] for f in desc['fields']])
        self.assertEqual(desc['version'], 1)


class BridgeBuildTest(unittest.TestCase):
    def test_options_without_server(self):
        class S:
            def get(self, *_a, **_k):
                raise RuntimeError('offline')

        old = bridge.SESSION
        bridge.SESSION = S()
        try:
            out = bridge.m_build_options({})
        finally:
            bridge.SESSION = old
        self.assertIn('transports', out['options'])
        self.assertEqual(out['profiles'], [])

    def test_validate_returns_fields(self):
        out = bridge.m_build_validate({'config': {
            'target_os': 'windows', 'output_format': 'exe',
            'transport_mode': 'smb'}})
        self.assertFalse(out['ok'])
        self.assertIn('smb_pipe', {e['field'] for e in out['errors']})


if __name__ == '__main__':
    unittest.main()
