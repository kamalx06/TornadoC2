"""Canonical provider endpoints.

Kept dependency-free so the config loader can resolve a default
without importing httpx or the provider modules. The providers
still carry their own ``DEFAULT_BASE`` as a runtime fallback.
"""

DEFAULT_BASE_URLS = {
    'anthropic':   'https://api.anthropic.com',
    'claude_code': '',
    'gemini':      'https://generativelanguage.googleapis.com',
    'groq':        'https://api.groq.com/openai',
    'ollama':      'http://localhost:11434',
    'openai':      'https://api.openai.com',
    'openrouter':  'https://openrouter.ai/api',
}


def default_base_url(provider: str) -> str:
    return DEFAULT_BASE_URLS.get((provider or '').lower(), '')
