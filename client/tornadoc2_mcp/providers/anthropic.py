"""Anthropic Claude API."""

import httpx

from ..errors import ProviderError
from .base import Provider, ChatResponse, ToolCall, register


@register
class AnthropicProvider(Provider):

    name = 'anthropic'
    supports_tools = True
    DEFAULT_BASE = 'https://api.anthropic.com'
    API_VERSION = '2023-06-01'
    DEFAULT_MODEL = 'claude-sonnet-4-5'

    async def chat(self, messages, tools=None, **kwargs):
        url = f"{self.base_url or self.DEFAULT_BASE}/v1/messages"
        body = {
            'model':       self.model or self.DEFAULT_MODEL,
            'max_tokens':  kwargs.get('max_tokens', 4096),
            'messages':    [m for m in messages
                            if m.get('role') != 'system'],
        }
        if kwargs.get('system'):
            body['system'] = kwargs['system']
        if tools:
            body['tools'] = [{
                'name':         t['name'],
                'description':  t['description'],
                'input_schema': t['input_schema'],
            } for t in tools]

        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(url, json=body, headers={
                'x-api-key':          self.api_key,
                'anthropic-version':  self.API_VERSION,
                'content-type':       'application/json',
            })
            if r.status_code >= 400:
                raise ProviderError(
                    f'anthropic HTTP {r.status_code}: {r.text[:500]}')
            data = r.json()

        content = ''
        tool_calls = []
        for block in data.get('content', []):
            if block['type'] == 'text':
                content += block['text']
            elif block['type'] == 'tool_use':
                tool_calls.append(ToolCall(
                    id=block['id'],
                    name=block['name'],
                    arguments=block['input'],
                ))
        return ChatResponse(
            content=content,
            tool_calls=tool_calls,
            stop_reason=data.get('stop_reason', 'end_turn'),
            usage=data.get('usage', {}),
        )