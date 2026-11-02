"""Tool dispatch pipeline.

Stages, in order:

    1. schema       — arguments validate against the tool's schema
    2. rate         — per-tool rate limit (expensive tools only)
    3. capability   — operator role holds the tool's capability
    4. allowlist    — verb/BOF is in the operator's local allowlist
    5. approval     — T3 tools require ApprovalState.PREAPPROVED
    6. execute      — call the handler
    7. envelope     — wrap in ToolResult (always, on success or error)

Each stage raises from `errors.py` on refusal. The dispatcher
converts the exception to a ToolResult with `ok=False`, so the
caller never has to catch.

Stages 3–5 are the reason the dispatcher exists. Without them,
every handler would need to re-implement three checks, and one
handler forgetting to would be the difference between "the AI
cannot run BOFs the operator hasn't allowed" and "the AI ran a
BOF". The pipeline makes it impossible to skip.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from . import errors, logging
from .adapter import ClientAdapter
from .approval import ApprovalState
from .config import AiConfig


def _get_tool(name):
    from .tools import get_tool
    return get_tool(name)


def _requires_approval(name):
    from .tools import requires_approval
    return requires_approval(name)


@dataclass
class ToolResult:
    """Uniform envelope every tool returns.

    The dispatcher returns this on both success and failure. The
    MCP protocol and the AI console both read the same shape.
    """
    ok: bool = True
    data: Any = None
    error: Optional[str] = None
    audit_id: Optional[str] = None
    elapsed_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'ok':         self.ok,
            'data':       self.data,
            'error':      self.error,
            'audit_id':   self.audit_id,
            'elapsed_ms': round(self.elapsed_ms, 2),
            'metadata':   self.metadata,
        }


@dataclass
class ToolContext:
    """What a handler receives.

    Handlers do not receive the dispatcher, the config, and the
    client as three separate arguments. They receive one context
    with everything they need. Adding a field to ToolContext does
    not require touching 34 handler signatures.
    """
    client: ClientAdapter
    cfg:    AiConfig
    logger: Any = logging

    # The tool's own name and tier, so the handler can log
    # consistently without hardcoding.
    name: str = ''
    tier: str = ''


# ---- Rate limiter (per tool, in-process) -----------------------------

_RATE_LOCK = asyncio.Lock()
_RATE_BUCKETS: dict[str, dict] = {}

# Only expensive tools are limited. A read of `list_beacons`
# should never fail because the operator also ran it 500
# times — the team server's own rate limiter already handles
# that. `build_agent` is different: a build occupies a server
# slot and a token bucket. Duplicating the rate limit here
# gives the operator a fast, clear error instead of a
# server-side 429 after a 30-second build attempt.
_TOOL_RATES = {
    'build_agent':         (1,  3),    # (per_sec, burst)
    'download_beacon_file': (1, 5),
    'screenshot_beacon':    (1, 5),
    'export_beacon':        (2, 5),
}


async def _rate_acquire(tool_name: str) -> None:
    limits = _TOOL_RATES.get(tool_name)
    if not limits:
        return
    per_sec, burst = limits
    now = time.monotonic()
    async with _RATE_LOCK:
        b = _RATE_BUCKETS.setdefault(
            tool_name, {'tokens': float(burst), 'last': now})
        elapsed = now - b['last']
        b['last'] = now
        b['tokens'] = min(burst, b['tokens'] + elapsed * per_sec)
        if b['tokens'] < 1.0:
            raise errors.ServerError(
                f'tool {tool_name!r} is rate-limited locally '
                f'({per_sec}/sec, burst {burst}). Wait before '
                f'retrying.',
                hint='this rate limit is on the operator side '
                     'and can be raised in dispatch._TOOL_RATES')
        b['tokens'] -= 1.0


# ---- Validation helpers ----------------------------------------------

_JSON_TYPES = {
    'string':  str,
    'integer': int,
    'number':  (int, float),
    'boolean': bool,
    'array':   list,
    'object':  dict,
}


def _validate_args(tool: dict, args: dict) -> None:
    """Minimal JSON-schema validation. Every tool schema uses
    only the constructs this function checks; a schema using
    something else would be a bug in tools/schemas.py.

    Types checked: type, required, enum. Nothing else.
    """
    schema = tool['input_schema']
    if schema.get('type') != 'object':
        raise errors.ValidationError(
            f'tool {tool["name"]!r} has a non-object schema')
    props = schema.get('properties') or {}
    req = schema.get('required') or []

    for k in req:
        if k not in args:
            raise errors.ValidationError(
                f'missing required argument: {k}')

    for k, v in args.items():
        spec = props.get(k)
        if spec is None:
            # Unknown keys are permitted — providers add their
            # own (e.g. Anthropic adds a `_provider` marker in
            # some versions). Extra keys are dropped by the
            # handler, not refused here.
            continue
        typ = spec.get('type')
        if typ and typ in _JSON_TYPES:
            expected = _JSON_TYPES[typ]
            if not isinstance(v, expected):
                raise errors.ValidationError(
                    f'argument {k!r} must be {typ}, '
                    f'got {type(v).__name__}')
        enum = spec.get('enum')
        if enum is not None and v not in enum:
            raise errors.ValidationError(
                f'argument {k!r} must be one of {enum}, got {v!r}')


# ---- The pipeline ----------------------------------------------------

async def dispatch(
    name: str,
    arguments: dict,
    client: ClientAdapter,
    cfg: AiConfig,
    *,
    approval: ApprovalState,
) -> ToolResult:
    """Dispatch one tool call through the pipeline.

    Never raises. On any refusal or error, returns a ToolResult
    with `ok=False`. The caller (agent loop or MCP server) reads
    the envelope.
    """
    started = time.monotonic()
    try:
        tool = _get_tool(name)
        if tool is None:
            raise errors.ValidationError(
                f'unknown tool: {name!r}',
                hint='the tool catalogue is served by '
                     'list_tools; call that first to see '
                     'which tool names are available')
        _validate_args(tool, arguments or {})
        await _rate_acquire(name)

        cap = tool.get('capability')
        if cap and cap not in client.capabilities:
            raise errors.CapabilityError(
                f'operator lacks capability {cap!r} for tool '
                f'{name!r}',
                hint=f'ask an admin to `operator set-role` your '
                     f'account, or use a role that includes '
                     f'{cap!r}')

        _check_allowlist(name, arguments, cfg)

        if _requires_approval(name) and approval != ApprovalState.PREAPPROVED:
            raise errors.ApprovalError(
                f'tool {name!r} requires operator approval',
                hint=('T3 tools are available only from '
                      '`beacon-client ai` — the approval '
                      'prompt has nowhere to appear in the '
                      'MCP protocol'))

        ctx = ToolContext(
            client=client, cfg=cfg,
            name=name, tier=tool['tier'])
        result = await tool['handler'](ctx, arguments or {})
        if not isinstance(result, ToolResult):
            result = ToolResult(ok=True, data=result)
        result.elapsed_ms = (time.monotonic() - started) * 1000.0
        return result

    except errors.McpError as exc:
        logging.warn('dispatch.refused',
                     tool=name, code=exc.code,
                     msg=str(exc))
        return ToolResult(
            ok=False,
            error=f'{exc.code}: {exc}',
            audit_id=exc.audit_id,
            elapsed_ms=(time.monotonic() - started) * 1000.0,
        )
    except Exception as exc:
        logging.error('dispatch.unhandled',
                      tool=name,
                      error=f'{type(exc).__name__}: {exc}')
        return ToolResult(
            ok=False,
            error=f'server_error: {type(exc).__name__}: {exc}',
            elapsed_ms=(time.monotonic() - started) * 1000.0,
        )


_BATCH_VERBS = {
    'ps_all':      'ps',
    'id_all':      'id',
    'netstat_all': 'netstat',
}


def _check_allowlist(name: str, args: dict,
                     cfg: AiConfig) -> None:
    """Per-verb and per-BOF allowlist, checked here so no
    handler can bypass it by having its own check.
    """
    verb = None
    if name == 'queue_task':
        verb = args.get('verb', '')
    elif name in _BATCH_VERBS:
        verb = _BATCH_VERBS[name]
    if verb is not None:
        allowed = cfg.mcp_allow_verbs
        if verb not in allowed:
            raise errors.AllowlistError(
                f'verb {verb!r} is not in mcp_allow_verbs',
                hint=('add the verb to mcp_allow_verbs in '
                      f'{cfg.source_path} if the operator '
                      'wants the AI to be able to queue it'))
    if name == 'run_bof':
        bof = args.get('name', '')
        allowed = cfg.mcp_allow_bofs
        if bof not in allowed:
            raise errors.AllowlistError(
                f'BOF {bof!r} is not in mcp_allow_bofs',
                hint=(f'add the BOF name to mcp_allow_bofs '
                      f'in {cfg.source_path}'))