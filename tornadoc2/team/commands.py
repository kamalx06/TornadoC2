"""Command catalogue.

The authoritative list of every command the operator console can
offer, with the capability each one requires. The team server filters
this by the requesting operator's role and sends the result to the
client, which renders it verbatim.

Adding a command means adding an entry here. The client never needs
to be rebuilt.

Field reference:
    name        — the verb the operator types
    args        — usage hint shown in help, e.g. "<path> [N]"
    description — one-line description
    capability  — required capability, or None for always-available
    category    — help section header
    scope       — 'main' (top-level menu) or 'beacon' (attached)
    native      — if True, the client passes the line through
                  unchanged; if False, the client may wrap it
    client_op   — if set, the client uses a specialised handler
                  instead of a plain task dispatch. Value matches a
                  branch in Client._cmd_beacon.
    platforms   — list of OS values the command makes sense on. None
                  means every platform.
"""

COMMANDS = [
    # =================================================================
    # Main menu — top-level commands, not attached to a beacon
    # =================================================================
    {
        'name': 'beacons', 'aliases': ['bl'],
        'args': '', 'description': 'list active beacons',
        'capability': 'beacon.list',
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'use', 'args': '<id>',
        'description': 'attach to a beacon',
        'capability': 'beacon.list',
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'detach', 'args': '',
        'description': 'detach from current beacon',
        'capability': 'beacon.list',
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'info', 'args': '',
        'description': 'show operator identity',
        'capability': None,
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'caps', 'args': '',
        'description': 'show your capabilities',
        'capability': None,
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'audit', 'aliases': ['tail', 'show', 'read'],
        'args': '[N] | chat [N]',
        'description': 'read your audit entries (or chat history)',
        'capability': 'audit.read.own',
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'chat', 'args': '',
        'description': 'enter team chat with other operators',
        'capability': 'chat.use',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'chat',
    },
    {
        'name': 'loot',
        'args': 'list | get <sha256> [<path>] | delete <sha256>',
        'description': 'browse and retrieve shared loot',
        'capability': 'loot.use',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'loot',
    },
    {
        'name': 'history', 'args': '',
        'description': 'show command history',
        'capability': None,
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'build', 'args': '[-c <file>]',
        'description': 'compile an agent on the server',
        'capability': 'beacon.build',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'build',
    },
    {
        'name': 'c2-profiles', 'aliases': ['c2p'],
        'args': '[<name>]',
        'description': 'list C2 profiles available for build '
                       '(or show one profile\'s full JSON)',
        'capability': 'beacon.build',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'c2_profiles',
    },
    {
        'name': 'bofs', 'aliases': ['bf'],
        'args': 'list | add <path> [--replace] | remove <name>',
        'description': 'manage the server-side BOF registry',
        'capability': 'beacon.build',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'bofs',
    },
    {
        'name': 'deadman', 'args': 'status',
        'description': "show the dead-man's switch state",
        'capability': 'deadman.view',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'deadman',
    },
    {
        'name': 'deadman',
        'args': 'status | arm <duration> | arm-until <HH:MM> | '
                'reset <duration> | disable | warn <f1,f2,...> | '
                'halt <none|shutdown|reboot> | '
                'shred <fast|random|dod|gutmann|nist|schneier'
                '|hmg|bsi|crypto|scrub|trim>',
        'description': "control the dead-man's switch",
        'capability': 'deadman.arm',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'deadman',
    },
    {
        'name': 'halt', 'args': '[--force]',
        'description': 'run the shutdown sequence now '
                       '(wipes state, optional power action)',
        'capability': 'deadman.halt',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'halt',
    },
    {
        'name': 'clear', 'aliases': ['cls'],
        'args': '',
        'description': 'clear the screen',
        'capability': None,
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'help', 'aliases': ['?'],
        'args': '',
        'description': 'this menu',
        'capability': None,
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'recipes', 'args': '[list | <name>]',
        'description': 'operator recipes — persistence, exfil, and '
                       'post-exploitation patterns to run via `sh`',
        'capability': None,
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'recipes',
    },
    {
        'name': 'exit', 'aliases': ['quit', 'q'],
        'args': '',
        'description': 'disconnect',
        'capability': None,
        'category': None, 'scope': 'main', 'native': False,
    },
    {
        'name': 'operators', 'aliases': ['op'],
        'args': 'passwd [<name>] | export [<path>]',
        'description': 'reset a password or export a config',
        'capability': 'operator.export.self',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'operators',
    },
    {
        'name': 'operators', 'aliases': ['op'],
        'args': 'list | add <name> <role> | remove <name> | '
                'set-role <name> <role> | passwd [<name>] | '
                'export [<name>] [<path>]',
        'description': 'manage remote operators',
        'capability': 'operator.list',
        'category': None, 'scope': 'main', 'native': False,
        'client_op': 'operators',
    },
    {
        'name': 'killall',
        'args': '--all | --stale | --tag <tag> | --ids <a,b,c>',
        'description': 'queue self-destruct on multiple beacons',
        'capability': 'beacon.use',
        'category': None, 'scope': 'main', 'native': False,
    },

    # =================================================================
    # Beacon scope — everything below requires an attached beacon
    # =================================================================

    # ---- Native inspection -----------------------------------------
    {'name': 'ls', 'args': '[path]',
     'description': 'Directory listing',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'cat', 'args': '<path>',
     'description': 'File read',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'readfile', 'args': '<path>',
     'description': 'Alias for cat',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True, 'hidden': True},
    {'name': 'find', 'args': '<path> [-name pat] [-size N] [-mtime N] [-type f|d]',
     'description': 'Recursive file search',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'grep', 'args': '<pat> <path> [-r] [-i] [-l]',
     'description': 'Content search',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'head', 'args': '<file> [-n N]',
     'description': 'First N lines (default 20)',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'tail', 'args': '<file> [-n N]',
     'description': 'Last N lines (default 20)',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'stat', 'args': '<path>',
     'description': 'File metadata',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'strings', 'args': '<file> [-n N]',
     'description': 'Printable string extraction',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'hexdump', 'args': '<file> [-n N] [-o offset]',
     'description': 'Hex + ASCII dump',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'sha1', 'args': '<file>',
     'description': 'SHA-1 hash',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'md5', 'args': '<file>',
     'description': 'MD5 hash',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'readlink', 'args': '<path>',
     'description': 'Resolve symlink',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True,
     'platforms': ['linux']},
    {'name': 'realpath', 'args': '<path>',
     'description': 'Canonical absolute path',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'du', 'args': '<path>',
     'description': 'Directory size',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'sha256', 'args': '<file>',
     'description': 'SHA-256 hash',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'cksum', 'args': '<file>',
     'description': 'CRC-32 + byte count',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'wc', 'args': '<file>',
     'description': 'Line / word / byte count',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'nl', 'args': '<file>',
     'description': 'Number non-empty lines',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'rev', 'args': '<file>',
     'description': 'Reverse each line',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'sort', 'args': '[-n] [-r] <file>',
     'description': 'Sort file lines',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'uniq', 'args': '<file>',
     'description': 'Collapse adjacent duplicate lines',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'tr', 'args': '<set1> <set2> <file> | -d <set> <file>',
     'description': 'Translate or delete bytes',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'base64', 'args': '[-e|-d] [-s] <file|string>',
     'description': 'Base64 encode or decode',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'which', 'args': '<cmd>',
     'description': 'Resolve cmd against PATH',
     'capability': 'beacon.use',
     'category': 'NATIVE — INSPECTION (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'ifconfig', 'args': '',
     'description': 'Network interfaces + addresses',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'netstat', 'args': '',
     'description': 'Listeners and established sockets',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'arp', 'args': '',
     'description': 'ARP cache',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'route', 'args': '',
     'description': 'Kernel routing table',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'users', 'args': '',
     'description': 'Local user accounts',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'groups', 'args': '',
     'description': 'Local groups',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'av-list', 'args': '',
     'description': 'Enumerate security products (WMI on Windows, '
                    'systemd units on Linux)',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},

    # ---- Native system ---------------------------------------------
    {'name': 'ps', 'args': '',
     'description': 'Process list',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'id', 'args': '',
     'description': 'uid / gid / groups',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'env', 'args': '',
     'description': 'Environment variables',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'pwd', 'args': '',
     'description': 'Current directory',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'whoami', 'args': '[/priv]',
     'description': 'Current user; /priv lists token privileges (Windows)',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'hostname', 'args': '',
     'description': 'Host name',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'uname', 'args': '',
     'description': 'OS + arch',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'df', 'args': '[path]',
     'description': 'Disk usage',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'uptime', 'args': '',
     'description': 'System uptime',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'date', 'args': '',
     'description': 'Current time',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'getpid', 'args': '',
     'description': "Beacon's PID",
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'getppid', 'args': '',
     'description': "Beacon's parent PID",
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},
    {'name': 'screenshot', 'args': '',
     'description': 'Interactive desktop capture (PNG, base64)',
     'capability': 'beacon.use',
     'category': 'NATIVE — SYSTEM (no subprocess)',
     'scope': 'beacon', 'native': True},

    # ---- Native file ops -------------------------------------------
    {'name': 'mkdir', 'args': '<path>',
     'description': 'Create directory tree',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True},
    {'name': 'rm', 'args': '[-r] <path>',
     'description': 'Remove file / tree',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True},
    {'name': 'cp', 'args': '<src> <dst>',
     'description': 'Copy file',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True},
    {'name': 'mv', 'args': '<src> <dst>',
     'description': 'Move / rename',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True},
    {'name': 'chmod', 'args': '<octal> <path>',
     'description': 'Change mode',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True,
     'platforms': ['linux']},
    {'name': 'ln', 'args': '[-s] <target> <linkpath>',
     'description': 'Create a symbolic link',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True,
     'platforms': ['linux']},
    {'name': 'touch', 'args': '[-r <ref>] <path>',
     'description': 'Create file, or copy a reference mtime',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True},
    {'name': 'gzip', 'args': '<file>',
     'description': 'Compress to <file>.gz',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True},
    {'name': 'gunzip', 'args': '<file.gz>',
     'description': 'Decompress to <file>',
     'capability': 'beacon.use',
     'category': 'NATIVE — FILE OPS',
     'scope': 'beacon', 'native': True},

    # ---- Execution -------------------------------------------------
    {'name': 'exec', 'args': '<cmd> [args...]',
     'description': 'Direct spawn; visible in argv',
     'capability': 'beacon.use',
     'category': 'EXECUTION',
     'scope': 'beacon', 'native': True},
    {'name': 'sh', 'args': '<cmd> [args...]',
     'description': 'Shell via stdin; command hidden from argv',
     'capability': 'beacon.use',
     'category': 'EXECUTION',
     'scope': 'beacon', 'native': True},
    {'name': 'make_token',
     'args': '<DOMAIN\\user> <password> | --revert',
     'description': 'Build a NEW_CREDENTIALS token and hold it. '
                    'Subsequent exec runs as that user. '
                    '`rev2self` drops it.',
     'capability': 'beacon.use',
     'category': 'EXECUTION',
     'scope': 'beacon', 'native': True,
     'platforms': ['windows']},
    {'name': 'rev2self', 'args': '',
     'description': 'Drop the held impersonation token',
     'capability': 'beacon.use',
     'category': 'EXECUTION',
     'scope': 'beacon', 'native': True,
     'platforms': ['windows']},
    {'name': 'runas',
     'args': '<DOMAIN\\user> <password> <command> [args...]',
     'description': 'Spawn a child process in a new logon session '
                    'under the supplied credentials. Returns the '
                    'PID; does not wait and does not capture output.',
     'capability': 'beacon.use',
     'category': 'EXECUTION',
     'scope': 'beacon', 'native': True,
     'platforms': ['windows']},

    # ---- Scheduling ------------------------------------------------
    {'name': 'sleep', 'args': '[N] [jitter]',
     'description': 'Change check-in interval',
     'capability': 'beacon.use',
     'category': 'SCHEDULING (applied server-side, immediate)',
     'scope': 'beacon', 'native': True},
    {'name': 'workhours', 'aliases': ['wh'],
     'args': '<start> <end> | off',
     'description': 'Set working-hours window',
     'capability': 'beacon.use',
     'category': 'SCHEDULING (applied server-side, immediate)',
     'scope': 'beacon', 'native': True},
    {'name': 'kill', 'args': '',
     'description': 'Queue self-destruct',
     'capability': 'beacon.use',
     'category': 'SCHEDULING (applied server-side, immediate)',
     'scope': 'beacon', 'native': True},

    # ---- Session tools ---------------------------------------------
    {'name': 'export', 'args': '[path]',
     'description': 'Write an HTML report locally',
     'capability': 'beacon.export',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False},
    {'name': 'socks', 'args': 'start <port> | stop | status',
     'description': 'Client-side SOCKS5 proxy',
     'capability': 'beacon.socks',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False,
     'client_op': 'socks'},
    {'name': 'info', 'args': '',
     'description': 'Show beacon identity and scheduling',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False,
     'client_op': 'info'},
    {'name': 'graph', 'args': '[tree|flat|summary|path <a> <b>]',
     'description': 'Engagement-wide shared-attribute graph',
     'capability': 'beacon.list',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False,
     'client_op': 'graph'},
    {'name': 'migrate',
     'args': '--self | <pid> | <process-name> [--method <name>]',
     'description': 'Detach a copy of the agent (--self), or inject '
                    'into a foreign process by PID or executable '
                    'basename. Injection requires a build with '
                    '"inject": true. --method default uses '
                    'CreateRemoteThread (Windows) or ptrace (Linux); '
                    '--method apc uses remote APC injection on '
                    'Windows. When omitted, the build-time default '
                    'is used.',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': True},
    {'name': 'forget', 'aliases': [],
     'args': '',
     'description': 'Delete this beacon from the registry',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False,
     'client_op': 'forget'},
    {'name': 'detach', 'args': '',
     'description': 'Return to the main menu',
     'capability': 'beacon.list',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False,
     'client_op': 'detach'},

    # ---- Task management -------------------------------------------
    {'name': 'tasks', 'args': '',
     'description': 'List outstanding tasks for this beacon',
     'capability': 'beacon.use',
     'category': 'TASK MANAGEMENT',
     'scope': 'beacon', 'native': False,
     'client_op': 'tasks'},
    {'name': 'wait', 'args': '[task-id]',
     'description': 'Block until pending task(s) complete',
     'capability': 'beacon.use',
     'category': 'TASK MANAGEMENT',
     'scope': 'beacon', 'native': False,
     'client_op': 'wait'},
    {'name': 'schedule',
     'args': 'add <N><u> <verb> [args] | list | remove <id>',
     'description': 'Recurring server-side task',
     'capability': 'beacon.use',
     'category': 'TASK MANAGEMENT',
     'scope': 'beacon', 'native': False,
     'client_op': 'schedule'},

    # ---- File transfer ---------------------------------------------
    {'name': 'upload', 'args': '<local> <remote>',
     'description': 'Chunked upload with SHA-256 verify',
     'capability': 'beacon.use',
     'category': 'FILE TRANSFER',
     'scope': 'beacon', 'native': False,
     'client_op': 'upload'},
    {'name': 'download',
     'args': '<remote> <local> [--no-loot]',
     'description': 'Chunked download with SHA-256 verify; '
                    'also stores to loot (pass --no-loot for a '
                    'private pull)',
     'capability': 'beacon.use',
     'category': 'FILE TRANSFER',
     'scope': 'beacon', 'native': False,
     'client_op': 'download'},

    # ---- In-memory scripts -----------------------------------------
    {'name': 'pyexec', 'args': '<local.py> [-- args]',
     'description': 'Python source via stdin',
     'capability': 'beacon.use',
     'category': 'IN-MEMORY SCRIPT EXECUTION',
     'scope': 'beacon', 'native': False,
     'client_op': 'script'},
    {'name': 'psexec', 'args': '<local.ps1> [-- args]',
     'description': 'PowerShell source via stdin',
     'capability': 'beacon.use',
     'category': 'IN-MEMORY SCRIPT EXECUTION',
     'scope': 'beacon', 'native': False,
     'client_op': 'script',
     'platforms': ['windows']},
    {'name': 'shexec', 'args': '<local.sh> [-- args]',
     'description': 'Shell source via stdin',
     'capability': 'beacon.use',
     'category': 'IN-MEMORY SCRIPT EXECUTION',
     'scope': 'beacon', 'native': False,
     'client_op': 'script'},

    # ---- In-memory payload execution -------------------------------
    {'name': 'execmem', 'args': '<remote> exe|elf [-- args]',
     'description': 'Execute a staged payload in memory',
     'capability': 'beacon.use',
     'category': 'IN-MEMORY PAYLOAD EXECUTION',
     'scope': 'beacon', 'native': False,
     'client_op': 'execmem'},

    {'name': 'execute-assembly',
     'args': '<local.exe> [-- args...]',
     'description': 'Run a .NET assembly in memory (Windows)',
     'capability': 'beacon.use',
     'category': 'IN-MEMORY PAYLOAD EXECUTION',
     'scope': 'beacon', 'native': False,
     'client_op': 'execute_assembly',
     'platforms': ['windows']},
    {'name': 'spawnto',
     'args': '[<path>] | --clear',
     'description': 'Set the sacrificial process that '
                    'execute-assembly spawns. Blank or --clear '
                    'reverts to the default worker staged under '
                    '%LOCALAPPDATA%. Applies on the next '
                    'check-in.',
     'capability': 'beacon.use',
     'category': 'IN-MEMORY PAYLOAD EXECUTION',
     'scope': 'beacon', 'native': True,
     'platforms': ['windows']},

    # ---- BOF --------------------------------------------------------
    {'name': 'bof', 'args': '<path.o> [args...]',
     'description': 'Run a local COFF file',
     'capability': 'beacon.use',
     'category': 'BEACON OBJECT FILES',
     'scope': 'beacon', 'native': False,
     'client_op': 'bof',
     'platforms': ['windows']},

    # ---- Extensions -------------------------------------------------
    {'name': 'extension',
     'args': 'list | info <name> | load <path.wasm> '
             '| unload <name> | list-loaded | call <name> [args]',
     'description': 'WASM extension host',
     'capability': 'beacon.use',
     'category': 'WASM EXTENSIONS',
     'scope': 'beacon', 'native': False,
     'client_op': 'extension'},

    # =================================================================
    # Operator-console feature verbs
    # =================================================================

    # ---- Beacon aliases and tags (SESSION TOOLS) -------------------
    {'name': 'alias', 'args': '[<name>]',
     'description': 'set or clear this beacon\'s alias',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False},
    {'name': 'tag', 'args': '<tag>',
     'description': 'add a tag to this beacon',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False},
    {'name': 'untag', 'args': '<tag>',
     'description': 'remove a tag from this beacon',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False},
    {'name': 'note', 'args': 'show | set <text> | clear',
     'description': 'per-beacon notes',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False},
    {'name': 'enablepriv',
     'args': '--list | --list-all | --vuln | <privilege> '
             '[--disable] | --all [--disable]',
     'description': 'List, enable, or disable Windows token '
                    'privileges on the current process (in-process)',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False,
     'client_op': 'enablepriv',
     'platforms': ['windows']},
    {'name': 'hashdump', 'args': '[<outdir>]',
     'description': 'Windows: read SAM + SYSTEM hives, decrypt '
                    'locally with secretsdump. Linux: merge '
                    '/etc/passwd and /etc/shadow into unshadow(8) '
                    'format.',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False,
     'client_op': 'hashdump'},
    {'name': 'lsassdump',
     'args': '--dump [--fork] [--duplicate] [--elevate] '
             '[--out <path>]',
     'description': 'LSASS minidump. The highest-signal verb in '
                    'the framework — every EDR watches for the '
                    'ProcessAccess event, the MiniDumpWriteDump '
                    'import, and the NtCreateProcessEx-from-'
                    'LSASS pattern. Runs in-process through '
                    'syscall; the operator accepts the signature '
                    'risk by typing the verb.',
     'capability': 'beacon.use',
     'category': 'SESSION TOOLS',
     'scope': 'beacon', 'native': False,
     'client_op': 'lsassdump',
     'platforms': ['windows']},

    # ---- Task queue management (TASK MANAGEMENT) -------------------
    {'name': 'cancel', 'args': '<task-id>',
     'description': 'cancel a queued task',
     'capability': 'beacon.use',
     'category': 'TASK MANAGEMENT',
     'scope': 'beacon', 'native': False},

    # ---- Main-scope feature commands -------------------------------
    {'name': 'creds',
     'args': 'list | get <id> | add [...] | search <term> | '
             'validate <id> | delete <id>',
     'description': 'shared credential vault',
     'capability': 'creds.use',
     'category': None, 'scope': 'main', 'native': False,
     'client_op': 'creds'},
    {'name': 'notes',
     'args': '[<text>] | search <term>',
     'description': 'engagement-wide notes',
     'capability': 'notes.use',
     'category': None, 'scope': 'main', 'native': False,
     'client_op': 'notes'},
    {'name': 'webhooks',
     'args': 'list | add --kind <slack|discord|telegram> '
             '--url <url> [--events ...] | remove <id> | test <id>',
     'description': 'Slack / Discord / Telegram notifications',
     'capability': 'webhooks.manage',
     'category': None, 'scope': 'main', 'native': False,
     'client_op': 'webhooks'},
]


def filter_for(role, capabilities, target_os=None):
    """Return the catalogue filtered to the entries this operator's
    role makes available.

    capabilities — the set of capabilities the role holds, computed
        by constants.ROLE_CAPABILITIES plus the LOCAL_ONLY filter.
    target_os    — if set, entries with a `platforms` list that does
        not include target_os are dropped.

    Duplicate names are collapsed: when two entries share a name
    (for example a baseline `operators` and an admin-only
    `operators`), only the LAST entry that passes the capability
    check is emitted. This is how a command's help text can vary
    by role without the client needing role-specific logic.
    """
    chosen = {}
    order = []
    for entry in COMMANDS:
        cap = entry.get('capability')
        if cap is not None and cap not in capabilities:
            continue
        if target_os and entry.get('platforms'):
            if target_os not in entry['platforms']:
                continue
        scope = entry.get('scope', 'main')
        key = (scope, entry['name'])
        view = {
            'name':        entry['name'],
            'aliases':     entry.get('aliases', []),
            'args':        entry.get('args', ''),
            'description': entry.get('description', ''),
            'category':    entry.get('category'),
            'native':      entry.get('native', False),
            'client_op':   entry.get('client_op'),
            'hidden':      entry.get('hidden', False),
        }
        if key not in chosen:
            order.append(key)
        chosen[key] = view

    out = {'main': [], 'beacon': []}
    for key in order:
        scope, _name = key
        out.setdefault(scope, []).append(chosen[key])
    return out


def categories_for(entries):
    """Return the ordered list of category names used by `entries`,
    in the order they first appear. Used by the client to build the
    help menu without hardcoding section headers."""
    seen = []
    for e in entries:
        cat = e.get('category')
        if cat and cat not in seen:
            seen.append(cat)
    return seen