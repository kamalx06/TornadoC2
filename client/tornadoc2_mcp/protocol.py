"""MCP stdio server.

    python -m tornadoc2_mcp -c alice.cfg

Speaks MCP over stdio. Every request is dispatched through the
same pipeline the AI console uses, so capability checks, the
verb allowlist, and audit attribution are identical — the only
difference is the approval gate: T3 tools are not exposed to an
external MCP client at all.

The server does not start the AI console, and the AI console
does not start this server. They are two frontends to the same
tool dispatcher.
"""

from __future__ import annotations

import asyncio
import json

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import errors, logging
from .adapter import ClientAdapter
from .approval import ApprovalState
from .config import AiConfig
from .dispatch import dispatch
from .tools import TOOLS, requires_approval


SERVER_NAME = 'tornadoc2-mcp'
SERVER_VERSION = '1.0.0'


def _tool_to_mcp(t: dict) -> Tool:
    return Tool(
        name=t['name'],
        description=t['description'],
        inputSchema=t['input_schema'],
    )


def _visible(client_caps: frozenset) -> list:
    """Tier 1 and 2 only. T3 requires approval, which the MCP
    client protocol has no way to surface — exposing them would
    let an external client silently invoke a T3 tool because the
    approval prompt has nowhere to appear.
    """
    out = []
    for t in TOOLS:
        if requires_approval(t['name']):
            continue
        cap = t.get('capability')
        if cap and cap not in client_caps:
            continue
        out.append(_tool_to_mcp(t))
    return out


def _result_to_content(result) -> list:
    """Convert a ToolResult to MCP Content blocks.

    Every result is returned as a single JSON text block with a
    stable top-level shape:

        {"ok": bool, "data": ..., "error": ..., "audit_id": ...}

    MCP clients that render structured content can parse it;
    clients that only render text get a readable blob.
    """
    body = {
        'ok':         result.ok,
        'data':       result.data,
        'error':      result.error,
        'audit_id':   result.audit_id,
        'elapsed_ms': round(result.elapsed_ms, 2),
        'metadata':   result.metadata,
    }
    return [TextContent(
        type='text',
        text=json.dumps(body, default=str, indent=2, sort_keys=True),
    )]


def build_server(client: ClientAdapter,
                 cfg: AiConfig) -> Server:
    srv = Server(SERVER_NAME, version=SERVER_VERSION)

    @srv.list_tools()
    async def _list():
        logging.debug('mcp.list_tools')
        try:
            return _visible(client.capabilities)
        except Exception as exc:
            logging.error(
                'mcp.list_tools_failed',
                err=f'{type(exc).__name__}: {exc}')
            return []

    @srv.call_tool()
    async def _call(name: str, arguments: dict):
        logging.info('mcp.call_tool', tool=name)
        try:
            result = await dispatch(
                name, arguments, client, cfg,
                approval=ApprovalState.NONE)
        except errors.ApprovalError as exc:
            return _result_to_content(_err_result(exc))
        except errors.McpError as exc:
            return _result_to_content(_err_result(exc))
        except Exception as exc:
            logging.error('mcp.unhandled', tool=name,
                          error=f'{type(exc).__name__}: {exc}')
            return _result_to_content(_err_result(
                errors.ServerError(f'{type(exc).__name__}: {exc}')))
        return _result_to_content(result)

    return srv


def _err_result(exc):
    from .dispatch import ToolResult
    return ToolResult(
        ok=False,
        error=f'{exc.code}: {exc}',
        audit_id=exc.audit_id,
    )


async def serve(cfg_path, cfg: AiConfig):
    """Async entrypoint used by `python -m tornadoc2_mcp`."""
    from .config import load_client_for_mcp
    client = await load_client_for_mcp(cfg_path)
    srv = build_server(client, cfg)
    async with stdio_server() as (read, write):
        logging.info('mcp.start', transport='stdio')
        try:
            await srv.run(
                read, write,
                srv.create_initialization_options())
        finally:
            logging.info('mcp.stop')