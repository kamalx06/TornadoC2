"""Groq (wire-compatible with OpenAI)."""

from .base import register
from .openai import OpenAIProvider


@register
class GroqProvider(OpenAIProvider):
    """Groq exposes the OpenAI Chat Completions wire format.

    Base URL carries the /openai prefix; the inherited chat()
    appends /v1/chat/completions, giving the documented
    https://api.groq.com/openai/v1/chat/completions endpoint.
    Auth is Authorization: Bearer, which the base class sets.
    """

    name = 'groq'
    DEFAULT_BASE = 'https://api.groq.com/openai'
    DEFAULT_MODEL = 'openai/gpt-oss-120b'