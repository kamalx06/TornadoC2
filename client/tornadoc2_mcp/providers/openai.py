"""OpenAI Chat Completions API."""

import json

import httpx

from ..errors import ProviderError
from .base import ChatResponse, Provider, ToolCall, register


@register
class OpenAIProvider(Provider):

    name = 'openai'
    supports_tools = True
    DEFAULT_BASE = 'https://api.openai.com'
    DEFAULT_MODEL = 'gpt-5.4-mini'

    def _headers(self) -> dict:
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type':  'application/json',
        }

    async def chat(self, messages, tools=None, **kwargs):
        url = f"{self.base_url or self.DEFAULT_BASE}/v1/chat/completions"
        body = {
            'model':       self.model or self.DEFAULT_MODEL,
            'messages':    _with_system(messages, kwargs.get('system')),
            'temperature': kwargs.get('temperature', self.temperature),
        }
        if kwargs.get('max_tokens'):
            body['max_tokens'] = int(kwargs['max_tokens'])
        if tools:
            body['tools'] = [{
                'type': 'function',
                'function': {
                    'name':        t['name'],
                    'description': t['description'],
                    'parameters':  t['input_schema'],
                },
            } for t in tools]
            body['tool_choice'] = 'auto'

        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(url, json=body, headers=self._headers())
            if r.status_code >= 400:
                raise ProviderError(
                    f'{self.name} HTTP {r.status_code}: '
                    f'{_body_excerpt(r)}')
            data = r.json()

        choice = data['choices'][0]
        msg = choice['message']
        content = msg.get('content') or ''
        tool_calls = []
        for call in msg.get('tool_calls') or []:
            try:
                args = json.loads(call['function']['arguments'])
            except Exception:
                args = {}
            tool_calls.append(ToolCall(
                id=call['id'],
                name=call['function']['name'],
                arguments=args,
            ))
        return ChatResponse(
            content=content,
            tool_calls=tool_calls,
            stop_reason=choice.get('finish_reason', 'stop'),
            usage=data.get('usage', {}),
        )


def _with_system(messages, system):
    if not system:
        return messages
    if messages and messages[0].get('role') == 'system':
        return messages
    return [{'role': 'system', 'content': system}] + list(messages)


def _body_excerpt(response) -> str:
    try:
        return response.text[:500]
    except Exception:
        return ''
