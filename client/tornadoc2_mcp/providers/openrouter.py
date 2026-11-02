"""OpenRouter (wire-compatible with OpenAI)."""

from .base import register
from .openai import OpenAIProvider


@register
class OpenRouterProvider(OpenAIProvider):
    """OpenRouter adds optional app-identification headers."""

    name = 'openrouter'
    DEFAULT_BASE = 'https://openrouter.ai/api'
    DEFAULT_MODEL = 'anthropic/claude-sonnet-4'

    def _headers(self) -> dict:
        headers = super()._headers()
        headers.update({
            'HTTP-Referer': 'https://tornadoc2.local',
            'X-Title':      'TornadoC2',
        })
        return headers
