"""Operator-side constants shared by the beacon handler and console.

This module is deliberately small. The beacon subsystem keeps its own
tunables under ``beacon/constants.py``. Anything that is genuinely
shared between the handler and the console — command lists, log
directory — lives here.

Keep this module limited to what the beacon handler and the
operator console both read. Feature-specific tunables belong in the
package that owns the feature:

  beacon/constants.py    beacon protocol tunables
  team/constants.py      roles, capabilities, team-server limits
  constants.py           command lists, log directory
"""

# ---------------------------------------------------------------------
# Top-level operator console commands.

MAIN_COMMANDS = (
    # Beacon inventory and control
    'beacons', 'bl',
    'beacon',
    'beacon-build', 'bbuild',
    'beacon-rm', 'beacon-forget',

    # Team server
    'multiplayer', 'mp',
    'operator',
    'audit',
    'deadman',
    'halt',
    'rotate-cookies', 'rotate',

    # Operator reference
    'recipes',

    # Meta
    'help', 'update'
    'exit', 'quit', 'q',
)


# ---------------------------------------------------------------------
# Commands offered for beacon submenu

BEACON_COMMANDS = (
    # session
    'help', 'exit', 'quit', 'detach',
    'info', 'tasks', 'wait',
    'sleep', 'workhours', 'wh',
    'socks', 'pivot',
    'steal_token',
    'kill', 'forget', 'remove',
    # transfer
    'upload', 'download',
    # execution
    'exec',
    'execmem', 'bof', 'bof-list',
    'pyexec', 'psexec', 'shexec',
    # extensions
    'extension',
    # scheduling
    'schedule',
    # reporting
    'export', 'graph',
    # native — inspection (added)
    'find', 'grep', 'head', 'tail', 'stat',
    'strings', 'hexdump', 'sha1', 'sha256', 'md5',
    'readlink', 'realpath', 'du',
    'wc', 'nl', 'rev', 'sort', 'uniq', 'tr', 'cksum',
    'base64', 'gzip', 'gunzip', 'which',
    # native — system (added)
    'ifconfig', 'netstat', 'arp', 'route',
    'users', 'groups', 'av-list',
    'df', 'uptime', 'date', 'getpid', 'getppid',
    'screenshot',
    # native — file ops (added)
    'mkdir', 'rm', 'cp', 'mv', 'chmod', 'ln', 'touch',
    # native — network (added)
    'curl', 'resolve', 'nc',
    # credential collection (added)
    'hashdump', 'enablepriv', 'lsassdump',
    # Windows credential / identity (added)
    'make_token', 'rev2self', 'runas',
)


# ---------------------------------------------------------------------
# Root of the on-disk log tree. SessionLogger writes per-session
# output under here; the team server's audit chain (logs/audit/),
# chat mirror (logs/chat/), and loot store (logs/lootstore/) are
# subdirectories; the beacon scheduler's schedules.json is a
# sibling file. One tree, so a backup or a `rm -rf` reaches
# everything.
#
# Sibling of `payloads/` (staged binaries) and `beacon_output/`
# (built agents); those live outside logs/ because they are not
# logs.

LOGS_DIR = 'logs'