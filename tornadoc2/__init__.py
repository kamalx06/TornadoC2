"""Beacon C2 — pull-based command-and-control framework.

The package is organised into three layers:

  * ``beacon_handler`` — the operator-side entry point. Owns the
    ECDSA signer, the TLS bootstrap, the operator console, and the
    ``beacon-build`` wizard.

  * ``beacon/`` — the server-side beacon subsystem. A Flask listener
    over TLS, a session registry with task dispatch, a protocol
    module, a session model, and an operator submenu.

  * ``agent/`` — the Go implant. A single binary cross-compiled from
    the operator machine. Every behavioural property is baked in at
    build time via ``-ldflags``. No runtime configuration.

Supporting modules (``session_log``, ``session_registry``,
``constants``) are shared between the handler and the beacon
engine.

See README.md for the operator reference, SECURITY.md for the
trust model, and CONTRIBUTING.md for development conventions.
"""

__version__ = '1.0.0'

__tool_name__ = 'TornadoC2'

def __getattr__(name):
    if name == 'BeaconHandler':
        from .beacon_handler import BeaconHandler
        return BeaconHandler
    if name == 'CommandSigner':
        from .beacon_handler import CommandSigner
        return CommandSigner
    if name == 'main':
        from .beacon_handler import main
        return main
    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    '__version__',
    '__tool_name__',
    'BeaconHandler',
    'CommandSigner',
    'main',
]