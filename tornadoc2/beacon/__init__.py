"""Beacon subsystem — pull-based implant handler.

Runs alongside the existing shell handler with no shared state and no
shared code paths. When the handler is started without --beacon-port
this package is never imported and the tool behaves exactly as before.

Public API:

    BeaconEngine      session registry and task dispatch
    BeaconListener    HTTP listener for beacon check-ins
    BeaconBuilder     cross-compile the Go agent
    BeaconConsole     operator submenu
"""

from .engine import BeaconEngine
from .listener import BeaconListener
from .session import BeaconSession
from .protocol import Task, Result
from .builder import BeaconBuilder, BeaconBuildConfig, OPSEC_PROFILES
from .console import BeaconConsole

__all__ = [
    'BeaconEngine',
    'BeaconListener',
    'BeaconSession',
    'Task',
    'Result',
    'BeaconBuilder',
    'BeaconBuildConfig',
    'OPSEC_PROFILES',
    'BeaconConsole',
]