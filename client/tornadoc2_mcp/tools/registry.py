"""Tool registry — built once at import time from schemas.py."""

from .schemas import TOOL_TABLE, build_schema
from .handlers import HANDLERS


def _build():
    out = []
    for name, tier, cap, desc, props, req in TOOL_TABLE:
        handler = HANDLERS.get(name)
        if handler is None:
            raise RuntimeError(
                f'tool {name!r} has a schema but no handler '
                f'in tools/handlers.py')
        out.append({
            'name':         name,
            'tier':         tier,
            'capability':   cap,
            'description':  desc,
            'input_schema': build_schema(props, req),
            'handler':      handler,
        })
    # Every handler must have a schema. A handler with no
    # schema cannot be discovered by the LLM.
    names = {t[0] for t in TOOL_TABLE}
    for name in HANDLERS:
        if name not in names:
            raise RuntimeError(
                f'handler {name!r} has no schema entry in '
                f'tools/schemas.py')
    return out


TOOLS = _build()
_BY_NAME = {t['name']: t for t in TOOLS}


def get_tool(name: str):
    return _BY_NAME.get(name)


def requires_approval(name: str) -> bool:
    t = get_tool(name)
    return bool(t and t['tier'] == 'T3')