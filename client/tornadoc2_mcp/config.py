"""ai.json schema.

A missing file is normal on a fresh client: it is auto-created
with the non-credential skeleton (allowlists, listener flags,
build dir) so the MCP server can run before an LLM is chosen.
Provider/model/key are only required when the AI console starts.

Every field is validated at load and at save. A malformed config
refuses before the console opens.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import errors
from .provider_defaults import default_base_url
from .paths import (
    AI_CONFIG as DEFAULT_AI_PATH,
    BUILD_DIR as DEFAULT_BUILD_DIR,
    ensure_state_dir,
)

SKELETON = {
    'mcp_allow_verbs': [],
    'mcp_allow_bofs': [],
    'mcp_allow_listener_create': False,
    'mcp_allow_listener_delete': False,
}

# Keys the editor owns. Unknown keys are preserved on save.
_KNOWN_KEYS = frozenset({
    'provider', 'model', 'api_key', 'base_url', 'temperature',
    'max_tokens', 'max_context_tokens', 'max_turns',
    'mcp_allow_verbs', 'mcp_allow_bofs',
    'mcp_allow_listener_create', 'mcp_allow_listener_delete',
    'build_output_dir',
})


@dataclass
class AiConfig:
    provider:     str = ''
    model:        str = ''
    api_key:      str = ''
    base_url:     str = ''
    temperature:  float = 0.7
    max_tokens:   int = 4096
    max_context_tokens: int = 128_000
    max_turns:    int = 40

    mcp_allow_verbs:  list = field(default_factory=list)
    mcp_allow_bofs:   list = field(default_factory=list)
    mcp_allow_listener_create: bool = False
    mcp_allow_listener_delete: bool = False

    build_output_dir: Path = field(
        default_factory=lambda: DEFAULT_BUILD_DIR)

    source_path: Path = field(default_factory=lambda: DEFAULT_AI_PATH)

    @property
    def is_complete(self) -> bool:
        """True when the provider block is usable."""
        if not self.provider or not self.model:
            return False
        if self.provider in ('ollama', 'claude_code'):
            return True
        return bool(self.api_key)


_VALID_PROVIDERS = (
    'anthropic', 'claude_code', 'gemini', 'groq', 'ollama',
    'openai', 'openrouter',
)
KEYLESS_PROVIDERS = frozenset({'ollama', 'claude_code'})


def ensure_ai_config(path=None) -> bool:
    """Create ``ai.json`` with SKELETON if it is missing.

    Returns True when a file was created. Existing files are
    never rewritten. Parent directory and file are ``0700`` /
    ``0600``.
    """
    path = Path(path or DEFAULT_AI_PATH).expanduser()
    if path.is_file():
        return False
    ensure_state_dir()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = {
        **SKELETON,
        'build_output_dir': str(DEFAULT_BUILD_DIR),
    }
    _atomic_write(path, body)
    return True


def load_ai_config(path=None, *, require_provider=False) -> AiConfig:
    path = Path(path or DEFAULT_AI_PATH).expanduser()
    ensure_ai_config(path)
    _check_perms(path)

    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise errors.ProviderNotConfiguredError(
            f'{path} is not valid JSON: {exc}')

    if not isinstance(raw, dict):
        raise errors.ProviderNotConfiguredError(
            f'{path} must be a JSON object')

    cfg = validate_raw(raw, path=path,
                       require_provider=require_provider)
    try:
        cfg.build_output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise errors.ProviderNotConfiguredError(
            f'{path}: cannot create build_output_dir '
            f'{cfg.build_output_dir}: {exc}')
    return cfg


def validate_raw(raw: dict, *, path, require_provider: bool) -> AiConfig:
    """Validate a raw mapping into AiConfig."""
    provider = _text(raw.get('provider')).lower()
    if provider:
        if provider not in _VALID_PROVIDERS:
            raise errors.ProviderNotConfiguredError(
                f'unknown provider {provider!r} in {path}',
                hint=f'valid providers: '
                     f'{", ".join(_VALID_PROVIDERS)}')
    elif require_provider:
        raise errors.ProviderNotConfiguredError(
            f'{path} has no "provider" configured',
            hint=f'run `ai config` (or GUI: Edit > AI settings) '
                 f'to choose one. Valid: '
                 f'{", ".join(_VALID_PROVIDERS)}')

    model = _text(raw.get('model'))
    if not model and require_provider:
        raise errors.ProviderNotConfiguredError(
            f'{path} has no "model" field',
            hint='run `ai config` (or GUI: Edit > AI settings)')

    api_key = _text(raw.get('api_key'))
    if (require_provider and provider
            and provider not in KEYLESS_PROVIDERS and not api_key):
        raise errors.ProviderNotConfiguredError(
            f'{path} has no "api_key" field (required for '
            f'{provider})',
            hint='run `ai config` (or GUI: Edit > AI settings)')

    try:
        temperature = float(raw.get('temperature', 0.7))
        max_tokens = int(raw.get('max_tokens', 4096))
        max_context_tokens = int(
            raw.get('max_context_tokens', 128_000))
        max_turns = int(raw.get('max_turns', 40))
    except (TypeError, ValueError) as exc:
        raise errors.ProviderNotConfiguredError(
            f'{path} has a non-numeric tuning value: {exc}')

    if temperature < 0 or temperature > 2:
        raise errors.ProviderNotConfiguredError(
            f'{path}: temperature must be 0-2 (got {temperature})')
    if max_tokens <= 0 or max_context_tokens <= 0 or max_turns <= 0:
        raise errors.ProviderNotConfiguredError(
            f'{path}: max_tokens, max_context_tokens and '
            f'max_turns must be positive')

    verbs = _string_list(raw.get('mcp_allow_verbs'),
                         'mcp_allow_verbs', path)
    bofs = _string_list(raw.get('mcp_allow_bofs'),
                        'mcp_allow_bofs', path)
    allow_create = _bool(raw.get('mcp_allow_listener_create', False),
                         'mcp_allow_listener_create', path)
    allow_delete = _bool(raw.get('mcp_allow_listener_delete', False),
                         'mcp_allow_listener_delete', path)

    base_url = _text(raw.get('base_url'))
    if base_url:
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            raise errors.ProviderNotConfiguredError(
                f'{path}: base_url must be an http(s) URL '
                f'(got {base_url!r})')
    else:
        base_url = default_base_url(provider)

    build_dir = _text(raw.get('build_output_dir'))
    build_output_dir = Path(
        build_dir or DEFAULT_BUILD_DIR).expanduser()

    return AiConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        max_tokens=max_tokens,
        max_context_tokens=max_context_tokens,
        max_turns=max_turns,
        mcp_allow_verbs=verbs,
        mcp_allow_bofs=bofs,
        mcp_allow_listener_create=allow_create,
        mcp_allow_listener_delete=allow_delete,
        build_output_dir=build_output_dir,
        source_path=path,
    )


def save_ai_config(path, patch: dict,
                   *, require_provider=False) -> AiConfig:
    """Validate and merge ``patch`` into the file atomically.

    Unknown existing keys survive. New keys the editor does not
    own are kept too. File mode is forced to ``0600``.
    """
    path = Path(path).expanduser()
    ensure_ai_config(path)
    _check_perms(path)
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise errors.ProviderNotConfiguredError(
            f'{path} is not valid JSON: {exc}')
    if not isinstance(raw, dict):
        raise errors.ProviderNotConfiguredError(
            f'{path} must be a JSON object')

    merged = dict(raw)
    for key, value in patch.items():
        if key in _KNOWN_KEYS:
            merged[key] = value
    # Validate before writing so a failed save leaves the old
    # file untouched.
    validate_raw(merged, path=path,
                 require_provider=require_provider)
    _atomic_write(path, merged)
    return load_ai_config(path, require_provider=require_provider)


def redacted_view(cfg: AiConfig) -> dict:
    """Config for display; the API key is never printed."""
    out = {
        'provider': cfg.provider,
        'model': cfg.model,
        'api_key': '***' if cfg.api_key else '',
        'base_url': cfg.base_url,
        'temperature': cfg.temperature,
        'max_tokens': cfg.max_tokens,
        'max_context_tokens': cfg.max_context_tokens,
        'max_turns': cfg.max_turns,
        'mcp_allow_verbs': list(cfg.mcp_allow_verbs),
        'mcp_allow_bofs': list(cfg.mcp_allow_bofs),
        'mcp_allow_listener_create': cfg.mcp_allow_listener_create,
        'mcp_allow_listener_delete': cfg.mcp_allow_listener_delete,
        'build_output_dir': str(cfg.build_output_dir),
        'configured': cfg.is_complete,
    }
    return out


def _atomic_write(path: Path, raw: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    body = json.dumps(raw, indent=2, sort_keys=True) + '\n'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(body)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


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


def _bool(value, key, path) -> bool:
    if isinstance(value, bool):
        return value
    raise errors.ProviderNotConfiguredError(
        f'{path}: {key} must be true or false')


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
