"""ai.json schema.

Every field is validated at load. A malformed config refuses
before the console opens — no half-working agent loop.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import errors


DEFAULT_AI_PATH = Path.home() / '.tornadoc2' / 'ai.json'
DEFAULT_BUILD_DIR = Path.home() / '.tornadoc2' / 'builds'


@dataclass
class AiConfig:
    provider:     str
    model:        str
    api_key:      str
    base_url:     str = ''
    temperature:  float = 0.7
    max_tokens:   int = 4096
    max_context_tokens: int = 128_000
    max_turns:    int = 40

    mcp_allow_verbs:  list = field(default_factory=list)
    mcp_allow_bofs:   list = field(default_factory=list)

    build_output_dir: Path = field(
        default_factory=lambda: DEFAULT_BUILD_DIR)

    source_path: Path = field(default_factory=lambda: DEFAULT_AI_PATH)


_VALID_PROVIDERS = (
    'anthropic', 'claude_code', 'gemini', 'groq', 'ollama',
    'openai', 'openrouter',
)


def load_ai_config(path) -> AiConfig:
    path = Path(path).expanduser()
    if not path.is_file():
        raise errors.ProviderNotConfiguredError(
            f'{path} not found',
            hint=_template_hint(path))

    _check_perms(path)

    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise errors.ProviderNotConfiguredError(
            f'{path} is not valid JSON: {exc}')

    if not isinstance(raw, dict):
        raise errors.ProviderNotConfiguredError(
            f'{path} must be a JSON object')

    provider = _text(raw.get('provider')).lower()
    if provider not in _VALID_PROVIDERS:
        raise errors.ProviderNotConfiguredError(
            f'unknown provider {provider!r} in {path}',
            hint=f'valid providers: '
                 f'{", ".join(_VALID_PROVIDERS)}')

    model = _text(raw.get('model'))
    if not model:
        raise errors.ProviderNotConfiguredError(
            f'{path} has no "model" field')

    api_key = _text(raw.get('api_key'))
    if provider != 'ollama' and provider != 'claude_code' \
            and not api_key:
        raise errors.ProviderNotConfiguredError(
            f'{path} has no "api_key" field (required for '
            f'{provider})')

    try:
        temperature = float(raw.get('temperature', 0.7))
        max_tokens = int(raw.get('max_tokens', 4096))
        max_context_tokens = int(
            raw.get('max_context_tokens', 128_000))
        max_turns = int(raw.get('max_turns', 40))
    except (TypeError, ValueError) as exc:
        raise errors.ProviderNotConfiguredError(
            f'{path} has a non-numeric tuning value: {exc}')

    if max_tokens <= 0 or max_context_tokens <= 0 or max_turns <= 0:
        raise errors.ProviderNotConfiguredError(
            f'{path}: max_tokens, max_context_tokens and '
            f'max_turns must be positive')

    verbs = _string_list(raw.get('mcp_allow_verbs'),
                         'mcp_allow_verbs', path)
    bofs = _string_list(raw.get('mcp_allow_bofs'),
                        'mcp_allow_bofs', path)

    build_dir = _text(raw.get('build_output_dir'))
    try:
        build_output_dir = Path(
            build_dir or DEFAULT_BUILD_DIR).expanduser()
    except (TypeError, ValueError) as exc:
        raise errors.ProviderNotConfiguredError(
            f'{path}: invalid build_output_dir: {exc}')

    cfg = AiConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=_text(raw.get('base_url')),
        temperature=temperature,
        max_tokens=max_tokens,
        max_context_tokens=max_context_tokens,
        max_turns=max_turns,
        mcp_allow_verbs=verbs,
        mcp_allow_bofs=bofs,
        build_output_dir=build_output_dir,
        source_path=path,
    )
    try:
        cfg.build_output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise errors.ProviderNotConfiguredError(
            f'{path}: cannot create build_output_dir '
            f'{cfg.build_output_dir}: {exc}')
    return cfg


async def load_client_for_mcp(cfg_path):
    """Load the operator's .cfg and return a ClientAdapter.

    The .cfg is the same file `beacon-client.py -c` reads. The
    Client constructor and its `connect()` method are the only
    things this function depends on — everything else goes
    through the adapter.
    """
    from .adapter import ClientAdapter
    cfg_path = Path(cfg_path).expanduser()
    if not cfg_path.is_file():
        raise errors.ProviderNotConfiguredError(
            f'operator config {cfg_path} not found',
            hint='run `operator export <name>` on the server '
                 'and copy the resulting .cfg here')
    if cfg_path.stat().st_mode & 0o077:
        raise errors.ProviderNotConfiguredError(
            f'{cfg_path} is readable by other users; '
            f'run `chmod 600 {cfg_path}`')

    # This import is the only place the MCP package touches
    # beacon-client.py. If the module path changes, change it
    # here.
    from tornado_client.repl import load_client_from_config

    try:
        client = await asyncio.to_thread(
            load_client_from_config, cfg_path)
    except (ValueError, OSError) as exc:
        raise errors.ProviderNotConfiguredError(
            f'operator config {cfg_path} is invalid: {exc}')
    except RuntimeError as exc:
        raise errors.TransportError(
            f'could not connect with {cfg_path}: {exc}',
            hint='check that the team server is running, '
                 'multiplayer is enabled, and the operator '
                 'password/HMAC clock are correct')
    except errors.McpError:
        raise
    except Exception as exc:
        raise errors.TransportError(
            f'could not load {cfg_path}: '
            f'{type(exc).__name__}: {exc}')
    return ClientAdapter(client)


def _text(value) -> str:
    if value is None:
        return ''
    if not isinstance(value, str):
        raise errors.ProviderNotConfiguredError(
            f'expected a string, got {type(value).__name__}')
    return value.strip()


def _string_list(value, key, path) -> list:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
            isinstance(v, str) for v in value):
        raise errors.ProviderNotConfiguredError(
            f'{path}: {key} must be a list of strings')
    return [v.strip() for v in value if v.strip()]


def _check_perms(path: Path) -> None:
    try:
        st = path.stat()
    except OSError:
        return
    if st.st_mode & 0o077:
        raise errors.ProviderNotConfiguredError(
            f'{path} is readable by other users '
            f'(mode {oct(st.st_mode & 0o777)})',
            hint=f'run `chmod 600 {path}`')


def _template_hint(path: Path) -> str:
    return (
        f'create {path}:\n'
        f'\n'
        f'  {{\n'
        f'    "provider": "anthropic",\n'
        f'    "model":    "claude-sonnet-4-5",\n'
        f'    "api_key":  "sk-ant-...",\n'
        f'    "mcp_allow_verbs": [\n'
        f'      "ls", "cat", "ps", "pwd", "whoami",\n'
        f'      "ifconfig", "netstat", "env"\n'
        f'    ],\n'
        f'    "mcp_allow_bofs": []\n'
        f'  }}\n'
        f'\n'
        f'Then `chmod 600 {path}`.'
    )