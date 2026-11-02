"""Tool schemas — compact declaration.

Every tool is one tuple:

    (name, tier, capability, description, properties, required)

`properties` is a dict of {name: {JSON-schema-fragment}}. The
fragments use only the constructs dispatch._validate_args
checks — `type`, `enum`, `description`. Anything richer would
pass the LLM but fail the dispatcher, which is worse than
having no schema at all.

The `description` is what the LLM reads to decide to call the
tool. Every one is written for that: imperative, concrete, no
jargon the model has to guess at.
"""

TOOL_TABLE = [
    # ---- Tier 1: read-only ------------------------------------------
    (
        'list_beacons', 'T1', 'beacon.list',
        'List every beacon on the engagement. Returns id, '
        'display name, alias, tags, os, arch, sleep interval, '
        'jitter, last-seen age, alive flag, viewer names, and '
        'the current spawnto path. Call this first before '
        'anything else.',
        {}, [],
    ),
    (
        'beacon_info', 'T1', 'beacon.use',
        'Full state of one beacon: identity, scheduling, work '
        'hours, kill deadline, spawn-to path, and pending '
        'tasks. Use this to answer questions about a specific '
        'host.',
        {'id': {'type': 'integer',
                'description': 'beacon ID (e.g. 1001)'}},
        ['id'],
    ),
    (
        'beacon_result', 'T1', 'beacon.use',
        'Fetch the result of a completed task. Pass `wait` to '
        'long-poll up to 5 seconds if the task has not '
        'finished. Returns output, exit code, error, and the '
        'task ID.',
        {'id':      {'type': 'integer'},
         'task_id': {'type': 'string'},
         'wait':    {'type': 'number'}},
        ['id', 'task_id'],
    ),
    (
        'beacon_tasks', 'T1', 'beacon.use',
        'List pending tasks on a beacon. Each row carries the '
        'verb, arguments, queue time, and the operator who '
        'queued it. Use before queueing more work.',
        {'id': {'type': 'integer'}},
        ['id'],
    ),
    (
        'list_listeners', 'T1', None,
        'Show the transports the team server is running: '
        'HTTP, QUIC, WebSocket, WireGuard, DNS, ICMP, and '
        'the pivot ports. Useful before recommending a build '
        'transport.',
        {}, [],
    ),
    (
        'list_profiles', 'T1', 'beacon.build',
        'List C2 profiles available for build (paths, '
        'User-Agent, shaping). Pass `name` for one profile\'s '
        'full JSON.',
        {'name': {'type': 'string',
                  'description': 'profile name (e.g. chrome)'}},
        [],
    ),
    (
        'list_bofs', 'T1', 'beacon.build',
        'List registered BOFs in the shared server-side '
        'registry. Returns name, arch, format, sha256, and '
        'source.',
        {}, [],
    ),
    (
        'list_loot', 'T1', 'loot.use',
        'List loot store entries: sha256, name, size, source '
        'beacon, uploader. Bytes are not exposed here — use '
        'download_from_loot if you need the file itself.',
        {}, [],
    ),
    (
        'list_creds', 'T1', 'creds.use',
        'List credential vault entries: id, user, domain, '
        'kind, validation status, source beacon. The password '
        'value is REDACTED in this view — use creds_reveal '
        '(requires approval) to see it.',
        {}, [],
    ),
    (
        'list_notes', 'T1', 'notes.use',
        'Read engagement-wide notes, or notes on one beacon. '
        'Engagement notes usually contain the scope '
        'document.',
        {'scope':     {'type': 'string',
                       'enum': ['engagement', 'beacon']},
         'beacon_id': {'type': 'integer'}},
        ['scope'],
    ),
    (
        'audit_tail', 'T1', 'audit.read.own',
        'Recent audit chain entries. Filter by operator, '
        'action, or beacon; or set `denied_only` to see only '
        'refused attempts.',
        {'limit':       {'type': 'integer'},
         'operator':    {'type': 'string'},
         'action':      {'type': 'string'},
         'beacon':      {'type': 'string'},
         'denied_only': {'type': 'boolean'}},
        [],
    ),
    (
        'chat_history', 'T1', 'chat.use',
        'Team chat history. Pass `peer` for the DM thread '
        'with that operator.',
        {'limit': {'type': 'integer'},
         'peer':  {'type': 'string'}},
        [],
    ),
    (
        'chat_who', 'T1', 'chat.use',
        'Operators currently at the chat prompt.',
        {}, [],
    ),
    (
        'graph_view', 'T1', 'beacon.list',
        'Engagement-wide shared-attribute graph. Modes: tree, '
        'flat, summary, path (requires src+dst).',
        {'mode': {'type': 'string',
                  'enum': ['tree', 'flat', 'summary', 'path']},
         'src':  {'type': 'integer'},
         'dst':  {'type': 'integer'}},
        ['mode'],
    ),
    (
        'get_command_catalogue', 'T1', 'commands.list',
        'The beacon-scope verb catalogue filtered for this '
        'operator\'s role and the target OS. Useful before '
        'queueing a task.',
        {'target_os': {'type': 'string',
                       'enum': ['linux', 'windows']}},
        [],
    ),

    # ---- Tier 2: safe mutations -------------------------------------
    (
        'queue_task', 'T2', 'beacon.use',
        'Queue one task on a beacon. The verb must appear in '
        'the operator\'s mcp_allow_verbs list. Returns the '
        'task ID and audit_id.',
        {'beacon_id': {'type': 'integer'},
         'verb':      {'type': 'string'},
         'args':      {'type': 'array'}},
        ['beacon_id', 'verb'],
    ),
    (
        'ps_all', 'T2', 'beacon.use',
        'Run `ps` on multiple beacons in one call and merge the '
        'results. Scope is all live beacons, those carrying a '
        'tag, an explicit id list, or beacons another operator '
        'is currently attached to. The verb must appear in '
        'mcp_allow_verbs. Returns per-beacon output and an '
        'ok/failed summary.',
        {'scope': {'type': 'string',
                   'enum': ['all', 'tag', 'ids', 'attached'],
                   'description': 'which live beacons to run on'},
         'tag':   {'type': 'string',
                   'description': 'required when scope=tag'},
         'ids':   {'type': 'array',
                   'description': 'required when scope=ids'},
         'timeout': {'type': 'integer',
                     'description': 'per-beacon timeout in seconds '
                                    '(default 120, max 900)'},
         'max_concurrent': {'type': 'integer',
                            'description': 'parallel beacons '
                                           '(default 4, max 5)'}},
        ['scope'],
    ),
    (
        'id_all', 'T2', 'beacon.use',
        'Run `id` on multiple beacons in one call and merge the '
        'results. Scope is all live beacons, those carrying a '
        'tag, an explicit id list, or beacons another operator '
        'is currently attached to. The verb must appear in '
        'mcp_allow_verbs. Returns per-beacon output and an '
        'ok/failed summary.',
        {'scope': {'type': 'string',
                   'enum': ['all', 'tag', 'ids', 'attached'],
                   'description': 'which live beacons to run on'},
         'tag':   {'type': 'string',
                   'description': 'required when scope=tag'},
         'ids':   {'type': 'array',
                   'description': 'required when scope=ids'},
         'timeout': {'type': 'integer',
                     'description': 'per-beacon timeout in seconds '
                                    '(default 120, max 900)'},
         'max_concurrent': {'type': 'integer',
                            'description': 'parallel beacons '
                                           '(default 4, max 5)'}},
        ['scope'],
    ),
    (
        'netstat_all', 'T2', 'beacon.use',
        'Run `netstat` on multiple beacons in one call and merge '
        'the results. Scope is all live beacons, those carrying '
        'a tag, an explicit id list, or beacons another operator '
        'is currently attached to. The verb must appear in '
        'mcp_allow_verbs. Returns per-beacon output and an '
        'ok/failed summary.',
        {'scope': {'type': 'string',
                   'enum': ['all', 'tag', 'ids', 'attached'],
                   'description': 'which live beacons to run on'},
         'tag':   {'type': 'string',
                   'description': 'required when scope=tag'},
         'ids':   {'type': 'array',
                   'description': 'required when scope=ids'},
         'timeout': {'type': 'integer',
                     'description': 'per-beacon timeout in seconds '
                                    '(default 120, max 900)'},
         'max_concurrent': {'type': 'integer',
                            'description': 'parallel beacons '
                                           '(default 4, max 5)'}},
        ['scope'],
    ),
    (
        'cancel_task', 'T2', 'beacon.use',
        'Cancel a task the operator queued before the beacon '
        'picked it up. Only the original operator can cancel.',
        {'beacon_id': {'type': 'integer'},
         'task_id':   {'type': 'string'}},
        ['beacon_id', 'task_id'],
    ),
    (
        'sleep_set', 'T2', 'beacon.use',
        'Change a beacon\'s sleep interval and jitter. Applies '
        'immediately on the server; the beacon picks it up on '
        'its next check-in.',
        {'beacon_id': {'type': 'integer'},
         'interval':  {'type': 'integer'},
         'jitter':    {'type': 'number'}},
        ['beacon_id', 'interval'],
    ),
    (
        'workhours_set', 'T2', 'beacon.use',
        'Change a beacon\'s working-hours window. Use "off" '
        'for 24/7.',
        {'beacon_id': {'type': 'integer'},
         'start':     {'type': 'string',
                       'description': 'HH:MM, or "off"'},
         'end':       {'type': 'string',
                       'description': 'HH:MM; omitted when '
                                      'start=off'}},
        ['beacon_id', 'start'],
    ),
    (
        'alias_set', 'T2', 'beacon.use',
        'Set or clear a beacon\'s friendly alias.',
        {'beacon_id': {'type': 'integer'},
         'alias':     {'type': 'string'}},
        ['beacon_id'],
    ),
    (
        'tag_op', 'T2', 'beacon.use',
        'Add or remove a tag on a beacon.',
        {'beacon_id': {'type': 'integer'},
         'op':        {'type': 'string',
                       'enum': ['add', 'remove']},
         'tag':       {'type': 'string'}},
        ['beacon_id', 'op', 'tag'],
    ),
    (
        'note_add', 'T2', 'notes.use',
        'Add a note. `scope: engagement` writes to the '
        'engagement-wide list; `scope: beacon` requires '
        'beacon_id.',
        {'scope':     {'type': 'string',
                       'enum': ['engagement', 'beacon']},
         'beacon_id': {'type': 'integer'},
         'text':      {'type': 'string'},
         'tags':      {'type': 'array'}},
        ['scope', 'text'],
    ),
    (
        'chat_send', 'T2', 'chat.use',
        'Send a message to the team chat room. Use kind '
        '"action" for /me-style messages.',
        {'text': {'type': 'string'},
         'kind': {'type': 'string',
                  'enum': ['chat', 'action']}},
        ['text'],
    ),
    (
        'build_agent', 'T2', 'beacon.build',
        'Compile an agent from a JSON config identical to '
        'beacon-build -c. Returns filename, size, sha256. '
        'The binary is streamed back and saved locally.',
        {'config_json': {'type': 'object'}},
        ['config_json'],
    ),
    (
        'export_beacon', 'T2', 'beacon.export',
        'Render an HTML report of one beacon session and '
        'save it locally. Returns the local path.',
        {'beacon_id': {'type': 'integer'}},
        ['beacon_id'],
    ),

    # ---- Tier 3: approval-gated -------------------------------------
    (
        'run_bof', 'T3', 'beacon.use',
        'Execute a registered BOF on a Windows beacon. The '
        'BOF name must appear in the operator\'s '
        'mcp_allow_bofs list. Requires operator approval.',
        {'beacon_id': {'type': 'integer'},
         'name':      {'type': 'string'},
         'args':      {'type': 'array'}},
        ['beacon_id', 'name'],
    ),
    (
        'creds_add', 'T3', 'creds.use',
        'Store a credential in the shared vault. The value '
        'is written to the vault but NOT to the audit chain. '
        'Requires operator approval.',
        {'user':          {'type': 'string'},
         'domain':        {'type': 'string'},
         'kind':          {'type': 'string'},
         'value':         {'type': 'string'},
         'source_beacon': {'type': 'integer'},
         'source_path':   {'type': 'string'}},
        ['user', 'kind', 'value'],
    ),
    (
        'creds_reveal', 'T3', 'creds.use',
        'Return the value of one credential. Every call is '
        'audited. Requires operator approval.',
        {'id': {'type': 'string'}},
        ['id'],
    ),
    (
        'creds_validate', 'T3', 'creds.use',
        'Run a credential validation on a beacon. One failed '
        'bind attempt per call — no retry, no fallback. '
        'Requires operator approval.',
        {'id':          {'type': 'string'},
         'from_beacon': {'type': 'integer'},
         'target':      {'type': 'string'}},
        ['id', 'from_beacon'],
    ),
    (
        'download_beacon_file', 'T3', 'beacon.use',
        'Chunked download of a file from a beacon. Pushes '
        'the result to the loot store. Requires operator '
        'approval.',
        {'beacon_id':   {'type': 'integer'},
         'remote_path': {'type': 'string'}},
        ['beacon_id', 'remote_path'],
    ),
    (
        'upload_beacon_file', 'T3', 'beacon.use',
        'Chunked upload of a local file to a beacon. '
        'Requires operator approval.',
        {'beacon_id':   {'type': 'integer'},
         'local_path':  {'type': 'string'},
         'remote_path': {'type': 'string'}},
        ['beacon_id', 'local_path', 'remote_path'],
    ),
    (
        'kill_beacon', 'T3', 'beacon.use',
        'Queue self-destruct on one beacon. Irreversible. '
        'Requires operator approval.',
        {'beacon_id': {'type': 'integer'}},
        ['beacon_id'],
    ),
    (
        'killall_beacons', 'T3', 'beacon.use',
        'Queue self-destruct on multiple beacons. '
        'Irreversible. Requires a two-part approval (yes, '
        'then the match count).',
        {'scope': {'type': 'string',
                   'enum': ['all', 'stale', 'tag', 'ids']},
         'tag':   {'type': 'string'},
         'ids':   {'type': 'array'}},
        ['scope'],
    ),
    (
        'screenshot_beacon', 'T3', 'beacon.use',
        'Capture the interactive desktop of a Windows '
        'beacon. Requires operator approval.',
        {'beacon_id': {'type': 'integer'}},
        ['beacon_id'],
    ),
]


def build_schema(props: dict, required: list) -> dict:
    return {
        'type':       'object',
        'properties': props,
        'required':   required,
    }