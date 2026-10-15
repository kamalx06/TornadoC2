"""WireGuard transport.

Kernel WireGuard on the team server, userspace WireGuard on the
target. The server creates a kernel WireGuard interface through
netlink (via pyroute2) and terminates the WireGuard handshake
there; the beacon runs a userspace WireGuard peer inside its own
process and connects to the server's tunnel IP. The C2 protocol
runs over the tunnel either way.

The keys are exchanged out of band: the server generates a keypair
on first run, writes the private half to `.keys/wireguard/server.key`,
and embeds the public half in every agent at build time (as
`WireGuardServerPubKey`). The operator generates an agent keypair
out of band with `wg genkey`, embeds the private half in the build,
and pins the public half on the server after deployment with
`wireguard add-peer <pubkey> <tunnel-ip>`.

Requirements on the team server:

  * `pyroute2` (`pip install pyroute2`).
  * The `wireguard` kernel module loaded (`modprobe wireguard`).
  * `CAP_NET_ADMIN` on the Python process — either run the handler
    as root, or `setcap cap_net_admin+ep $(which python3)`.
  * `wireguard-tools` on `PATH` for the one-time server keypair
    generation on first launch (the `wg` command). Not required
    after the key file exists.

The agent side has no runtime dependency: the userspace WireGuard
stack is linked into the binary at build time.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading

try:
    from pyroute2 import IPRoute
    from pyroute2 import WireGuard
    _PYROUTE2 = True
except ImportError:
    _PYROUTE2 = False

from .base import Transport

log = logging.getLogger(__name__)

WG_INTERFACE_DEFAULT = 'tornado0'
WG_PORT_DEFAULT = 51820
WG_SUBNET_DEFAULT = '10.99.0.0/24'
WG_SERVER_IP_DEFAULT = '10.99.0.1'


class WireGuardTransport(Transport):

    name = 'wireguard'

    def __init__(self, engine, host, port, config=None):
        super().__init__(engine, host, port, config)
        self._server_pubkey = None
        self._private_key = None
        self._peers = {}     # pubkey -> allowed_ips (always /32)
        self._lock = threading.Lock()
        self._thread = None
        self._running = False
        self._ipr = None
        self._wg = None
        cfg = config or {}
        self.wg_interface = cfg.get(
            'interface', WG_INTERFACE_DEFAULT)
        self.wg_port      = int(cfg.get('port', WG_PORT_DEFAULT))
        self.wg_subnet    = cfg.get('subnet', WG_SUBNET_DEFAULT)
        self.wg_server_ip = cfg.get(
            'server_ip', WG_SERVER_IP_DEFAULT)
        try:
            self.wg_prefixlen = int(self.wg_subnet.split('/')[1])
        except (IndexError, ValueError):
            self.wg_prefixlen = 24

    # ------------------------------------------------------------------
    # Key management

    def _load_or_generate_key(self) -> str:
        path = '.keys/wireguard/server.key'
        if os.path.isfile(path):
            with open(path, 'rb') as fh:
                return fh.read().decode('ascii').strip()

        os.makedirs(os.path.dirname(path), exist_ok=True)
        r = subprocess.run(['wg', 'genkey'],
                           capture_output=True, check=True)
        private = r.stdout.decode('ascii').strip()
        with open(path, 'wb') as fh:
            fh.write(private.encode('ascii'))
        os.chmod(path, 0o600)

        r2 = subprocess.run(['wg', 'pubkey'],
                            input=private.encode(),
                            capture_output=True, check=True)
        public = r2.stdout.decode('ascii').strip()
        log.info("wireguard: generated server keypair "
                 "(pubkey %s)", public)
        return private

    def server_pubkey(self) -> str:
        if self._server_pubkey is None:
            priv = self._load_or_generate_key()
            r = subprocess.run(['wg', 'pubkey'],
                               input=priv.encode(),
                               capture_output=True, check=True)
            self._server_pubkey = r.stdout.decode('ascii').strip()
        return self._server_pubkey

    def add_peer(self, pubkey: str, allowed_ip: str):
        """Called from the console: `wireguard add-peer <pubkey>`.

        `allowed_ip` may be a bare IPv4 (`10.99.0.2`) or a CIDR
        (`10.99.0.2/32`). pyroute2.WireGuard requires CIDR, so
        the bare form is normalised before the call. An operator
        who types the bare form (the common case) gets a peer
        configured the same way as one who types the CIDR.
        """
        if '/' not in allowed_ip:
            allowed_ip = allowed_ip + '/32'
        with self._lock:
            self._peers[pubkey] = allowed_ip
        if self._wg is not None:
            try:
                self._wg.set(
                    self.wg_interface,
                    peer={pubkey: {'allowed_ips': [allowed_ip]}})
                log.info("wireguard: peer %s added (%s)",
                         pubkey[:8], allowed_ip)
            except Exception as exc:
                log.error("wireguard: add peer: %s", exc)

    def remove_peer(self, pubkey: str):
        with self._lock:
            self._peers.pop(pubkey, None)
        if self._wg is not None:
            try:
                self._wg.set(self.wg_interface,
                             peer={pubkey: {'remove': True}})
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Lifecycle

    def start(self):
        if not _PYROUTE2:
            log.error("wireguard: pyroute2 not installed "
                      "(pip install pyroute2)")
            return False
        if os.geteuid() != 0:
            log.error("wireguard: requires root or CAP_NET_ADMIN")
            return False

        import shutil as _shutil
        if _shutil.which('wg') is None:
            log.error("wireguard: `wg` not found on PATH — install "
                      "wireguard-tools, or pre-generate the server "
                      "key at .keys/wireguard/server.key")
            return False

        try:
            self._private_key = self._load_or_generate_key()
            self._ipr = IPRoute()
            self._wg = WireGuard()
            self._setup_interface()
        except Exception as exc:
            log.error("wireguard: setup failed: %s", exc)
            return False

        self._running = True
        log.info("wireguard: listening on %s:%d (subnet %s)",
                 self.host, self.wg_port, self.wg_subnet)

        self._thread = threading.Thread(
            target=self._http_loop, daemon=True)
        self._thread.start()
        return True

    def _setup_interface(self):
        try:
            self._ipr.link('add',
                           ifname=self.wg_interface,
                           kind='wireguard')
        except Exception:
            pass

        self._wg.set(self.wg_interface,
                     private_key=self._private_key,
                     listen_port=self.wg_port)

        self._ipr.link('set', index=self._if_index(),
                       state='up')

        self._ipr.addr('add', index=self._if_index(),
                       address=self.wg_server_ip,
                       prefixlen=self.wg_prefixlen)

        with self._lock:
            for pub, ip in self._peers.items():
                try:
                    self._wg.set(
                        self.wg_interface,
                        peer={pub: {'allowed_ips': [ip]}})
                except Exception as exc:
                    log.error("wireguard: peer %s: %s",
                              pub[:8], exc)

    def _if_index(self) -> int:
        idx = self._ipr.link_lookup(ifname=self.wg_interface)
        if not idx:
            raise RuntimeError("wireguard: interface missing")
        return idx[0]

    def _http_loop(self):
        """No-op.

        The WireGuard transport does not need an inner HTTPS
        listener. The outer BeaconListener binds 0.0.0.0 on the
        beacon port, so it already accepts traffic that arrives
        through the WireGuard tunnel — a packet that comes in on
        tornado0 is routed to the same socket the outer listener
        is already serving. Running a second listener on
        10.99.0.1:8881 would collide with the outer one on Linux
        (`EADDRINUSE`), because binding 0.0.0.0:8881 claims the
        port on every interface including the tunnel.

        The method is kept so the start() call that spawns this
        thread does not need to change; a future revision that
        wants a distinct certificate or mTLS policy on the
        tunnel side could restore a real body here, but only
        after moving the outer listener to a specific interface
        (--host 1.2.3.4 instead of the default 0.0.0.0).
        """
        log.info("wireguard: tunnel up on %s/%d; outer HTTP "
                 "listener on %s:%d serves tunnel traffic",
                 self.wg_interface, self.wg_port,
                 self.host, self.port)

    def stop(self):
        self._running = False
        try:
            if self._ipr is not None:
                self._ipr.link('del', index=self._if_index())
        except Exception:
            pass
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None