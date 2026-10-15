"""Team server constants: roles, capabilities, tunables."""

DEFAULT_OPERATOR_PORT = 31337

ROLES = ('viewer', 'guardian', 'operator', 'admin', 'local')


def role_at_least(role: str, minimum: str) -> bool:
    try:
        return ROLES.index(role) >= ROLES.index(minimum)
    except ValueError:
        return False

ROLE_CAPABILITIES = {
    'viewer': frozenset({
        'beacon.list',
        'audit.read.own',
        'commands.list',
        'chat.use',
        'operator.export.self',
        'operator.passwd.self',
        'deadman.view',
    }),
    'operator': frozenset({
        'beacon.list', 'beacon.use',
        'beacon.export', 'beacon.socks',
        'beacon.build',
        'audit.read.own',
        'commands.list',
        'chat.use',
        'loot.use',
        'creds.use',
        'notes.use',
        'webhooks.manage',
        'operator.export.self',
        'operator.passwd.self',
        'deadman.view',
    }),
    'guardian': frozenset({
        'commands.list',
        'audit.read.own',
        'chat.use',
        'operator.export.self',
        'operator.passwd.self',
        'deadman.view',
        'deadman.arm',
        'deadman.halt',
    }),
    'admin': frozenset({
        'beacon.list', 'beacon.use',
        'beacon.export', 'beacon.socks',
        'beacon.build',
        'audit.read.own',
        'commands.list',
        'chat.use',
        'loot.use',
        'creds.use',
        'notes.use',
        'webhooks.manage',
        'webhooks.manage.admin',
        'audit.read.all',
        'operator.list',
        'operator.add',
        'operator.remove',
        'operator.set_role',
        'operator.export.self',
        'operator.export.other',
        'operator.passwd.self',
        'operator.passwd.other',
        'deadman.view',
    }),
    'local': frozenset({
        'beacon.list', 'beacon.info', 'beacon.use', 'beacon.forget',
        'extension.list', 'extension.use',
        'audit.read.own', 'audit.read.all', 'audit.checkpoint',
        'audit.verify',
        'operator.list', 'operator.add', 'operator.add.admin',
        'operator.remove', 'operator.remove.admin',
        'operator.set_role', 'operator.set_role.admin',
        'operator.passwd.self', 'operator.passwd.other',
        'operator.passwd.other.admin',
        'operator.export.self', 'operator.export.other',
        'operator.export.other.admin',
        'deadman.view', 'deadman.arm', 'deadman.halt',
        'chat.use', 'loot.use', 'notes.use',
        'multiplayer.toggle',
        'webhooks.manage', 'webhooks.manage.admin',
        'ca.rotate', 'creds.use',
    }),
}

LOCAL_ONLY = frozenset({
    'multiplayer.toggle',
    'operator.add.admin',
    'operator.remove.admin',
    'operator.set_role.admin',
    'operator.export.other.admin',
    'operator.passwd.other.admin',
    'ca.rotate',
    'audit.checkpoint',
    'audit.verify',
})


def has_capability(role: str, capability: str, is_local: bool) -> bool:
    """Return True only if the role has the capability AND the
    source is permitted to hold it."""
    if capability in LOCAL_ONLY and not is_local:
        return False
    return capability in ROLE_CAPABILITIES.get(role, frozenset())


DEFAULT_ROLE = 'operator'
MAX_OPERATORS = 32
MAX_REQUEST_BYTES = 90 * 1024 * 1024
AUDIT_DIR = 'logs/audit'
TEAM_CA_DIR = 'team_ca'
RATE_PER_SEC = 100.0
RATE_BURST = 1000
CHAT_PER_SEC = 3.0
CHAT_BURST = 10
CHAT_LOG_DIR = 'logs/chat'
LOOT_DIR = 'logs/lootstore'
BUILD_PER_HOUR = 50
BUILD_CONCURRENT_PER_OPERATOR = 2
BUILD_CONCURRENT_GLOBAL = 4
BUILD_STAGE_TTL = 1800
BUILD_CHUNK_SIZE = 512 * 1024
BUILD_STAGE_DIR = 'beacon_output/remote'