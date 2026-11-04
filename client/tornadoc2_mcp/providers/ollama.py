"""Local Ollama."""

import json

import httpx

from ..errors import ProviderError
from .base import ChatResponse, Provider, ToolCall, register


@register
class OllamaProvider(Provider):

    name = 'ollama'
    supports_tools = True
    DEFAULT_BASE = 'http://localhost:11434'
    DEFAULT_MODEL = 'llama3.3'

    async def chat(self, messages, tools=None, **kwargs):
        url = f"{self.base_url or self.DEFAULT_BASE}/api/chat"
        body = {
            'model':    self.model or self.DEFAULT_MODEL,
            'messages': _with_system(messages, kwargs.get('system')),
            'stream':   False,
            'options':  {
                'temperature': kwargs.get('temperature', self.temperature),
            },
        }
        if kwargs.get('max_tokens'):
            body['options']['num_predict'] = int(kwargs['max_tokens'])
        if tools:
            body['tools'] = [{
                'type': 'function',
                'function': {
                    'name':        t['name'],
                    'description': t['description'],
                    'parameters':  t['input_schema'],
                },
            } for t in tools]

        async with httpx.AsyncClient(timeout=300) as client:
            r = await client.post(url, json=body)
            if r.status_code >= 400:
                raise ProviderError(
                    f'ollama HTTP {r.status_code}: {r.text[:500]}')
            data = r.json()

        msg = data.get('message') or {}
        content = msg.get('content') or ''
        tool_calls = []
        for call in msg.get('tool_calls') or []:
            args = call.get('function', {}).get('arguments') or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            tool_calls.append(ToolCall(
                id=call.get('id', '') or f'call_{len(tool_calls)}',
                name=call.get('function', {}).get('name', ''),
                arguments=args,
            ))
        return ChatResponse(
            content=content,
            tool_calls=tool_calls,
            stop_reason=data.get('done_reason', 'stop'),
            usage={},
        )


def _with_system(messages, system):
    if not system:
        return messages
    if messages and messages[0].get('role') == 'system':
        return messages
    return [{'role': 'system', 'content': system}] + list(messages)
