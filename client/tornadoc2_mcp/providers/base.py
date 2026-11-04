"""Provider ABC and factory."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from ..errors import ProviderNotConfiguredError


@dataclass
class ToolCall:
    id:        str
    name:      str
    arguments: dict


@dataclass
class ChatResponse:
    content:     str = ''
    tool_calls:  list = field(default_factory=list)
    stop_reason: str = 'end_turn'
    usage:       dict = field(default_factory=dict)


class Provider(abc.ABC):
    name: str = ''
    supports_tools: bool = True
    DEFAULT_MODEL: str = ''

    def __init__(self, api_key='', base_url='', model='',
                 temperature=0.7, **kwargs):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model or self.DEFAULT_MODEL
        self.temperature = temperature
        self.extra = kwargs

    @abc.abstractmethod
    async def chat(self, messages, tools=None, **kw) -> ChatResponse:
        ...


_PROVIDERS = {}


def register(cls):
    _PROVIDERS[cls.name] = cls
    return cls


def build_provider(cfg: dict) -> Provider:
    name = (cfg.get('provider') or 'anthropic').lower()
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ProviderNotConfiguredError(
            f'unknown provider {name!r}; valid: '
            f'{", ".join(sorted(_PROVIDERS))}')
    return cls(
        api_key=cfg.get('api_key', ''),
        base_url=cfg.get('base_url', ''),
        model=cfg.get('model', ''),
        temperature=cfg.get('temperature', 0.7),
    )