"""Google Gemini (generativelanguage.googleapis.com).

Not OpenAI-compatible. Gemini uses `contents` / `parts`, the
`model` role instead of `assistant`, `systemInstruction` at the
top level, function declarations without IDs, and SSE frames
without a `[DONE]` terminator.

The internal transcript shape this provider receives is the one
loop.py produces:

  {'role': 'user',      'content': str}
  {'role': 'assistant', 'content': str, 'tool_calls': [{id, name, arguments}]}
  {'role': 'tool',      'tool_call_id': str, 'content': str}
  {'role': 'system',    'content': str}

Conversion to Gemini's shape happens here, so loop.py stays
unchanged.
"""

import json

import httpx

from ..errors import ProviderError
from .base import ChatResponse, Provider, ToolCall, register, StreamEvent


# Keys Gemini's Schema object does not accept. Stripped recursively
# so a JSON-Schema tool definition passes through without a 400.
_SCHEMA_DROP = ('$schema', 'additionalProperties', '$id', '$ref')


@register
class GeminiProvider(Provider):

    name = 'gemini'
    supports_tools = True
    DEFAULT_BASE = 'https://generativelanguage.googleapis.com'
    DEFAULT_MODEL = 'gemini-3.5-flash'

    # ------------------------------------------------------------------
    # Request construction
    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        return {
            'x-goog-api-key': self.api_key,
            'Content-Type':   'application/json',
        }

    def _body(self, messages, tools, kwargs, stream: bool) -> dict:
        system_text, contents = _to_contents(messages)

        body = {
            'contents': contents,
            'generationConfig': {
                'temperature': kwargs.get(
                    'temperature', self.temperature),
            },
        }
        if kwargs.get('max_tokens'):
            body['generationConfig']['maxOutputTokens'] = int(
                kwargs['max_tokens'])
        if system_text:
            body['systemInstruction'] = {
                'parts': [{'text': system_text}],
            }
        if tools:
            body['tools'] = [{
                'functionDeclarations': [{
                    'name':        t['name'],
                    'description': t['description'],
                    'parameters':  _clean_schema(t['input_schema']),
                } for t in tools],
            }]
        return body

    def _url(self, stream: bool) -> str:
        base = self.base_url or self.DEFAULT_BASE
        model = self.model or self.DEFAULT_MODEL
        method = 'streamGenerateContent' if stream else 'generateContent'
        url = f'{base}/v1beta/models/{model}:{method}'
        if stream:
            url += '?alt=sse'
        return url

    # ------------------------------------------------------------------
    # Non-streaming
    # ------------------------------------------------------------------

    async def chat(self, messages, tools=None, **kwargs):
        body = self._body(messages, tools, kwargs, stream=False)

        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(
                self._url(False), json=body, headers=self._headers())
            if r.status_code >= 400:
                raise ProviderError(
                    f'gemini HTTP {r.status_code}: {r.text[:500]}')
            data = r.json()

        content, tool_calls, stop_reason = _parse_candidate(data)
        return ChatResponse(
            content=content,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=_usage(data),
        )

    # ------------------------------------------------------------------
    # Streaming
    # ------------------------------------------------------------------

    async def chat_stream(self, messages, tools=None, **kwargs):
        body = self._body(messages, tools, kwargs, stream=True)

        text_accum = ''
        tool_calls = []
        stop_reason = 'end_turn'
        usage = {}

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                    'POST', self._url(True), json=body,
                    headers=self._headers()) as r:
                if r.status_code >= 400:
                    err = (await r.aread()).decode('utf-8', 'replace')
                    raise ProviderError(
                        f'gemini HTTP {r.status_code}: {err[:500]}')

                async for line in r.aiter_lines():
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if not stripped.startswith('data: '):
                        continue
                    payload = stripped[len('data: '):].strip()
                    if not payload or payload == '[DONE]':
                        continue

                    try:
                        chunk = json.loads(payload)
                    except Exception:
                        continue

                    chunk_text, chunk_tools, reason = _parse_candidate(
                        chunk)
                    if chunk_text:
                        text_accum += chunk_text
                        yield StreamEvent(kind='text', text=chunk_text)
                    if chunk_tools:
                        tool_calls.extend(chunk_tools)
                    if reason and reason != 'end_turn':
                        stop_reason = reason

                    chunk_usage = _usage(chunk)
                    if chunk_usage:
                        usage.update(chunk_usage)

        response = ChatResponse(
            content=text_accum,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            usage=usage,
        )
        if usage:
            yield StreamEvent(kind='usage', usage=usage)
        yield StreamEvent(kind='done', response=response)


# ----------------------------------------------------------------------
# Transcript conversion
# ----------------------------------------------------------------------

def _to_contents(messages):
    """Return (system_text, contents) in Gemini's shape."""
    system_chunks = []
    id_to_name = {}
    contents = []

    for m in messages:
        role = m.get('role', 'user')
        content = m.get('content') or ''

        if role == 'system':
            if content:
                system_chunks.append(content)
            continue

        if role == 'user':
            if content:
                contents.append({
                    'role':  'user',
                    'parts': [{'text': content}],
                })
            continue

        if role == 'assistant':
            parts = []
            if content:
                parts.append({'text': content})
            for tc in (m.get('tool_calls') or []):
                id_to_name[tc.get('id', '')] = tc.get('name', '')
                parts.append({
                    'functionCall': {
                        'name': tc.get('name', ''),
                        'args': tc.get('arguments') or {},
                    },
                })
            if parts:
                contents.append({'role': 'model', 'parts': parts})
            continue

        if role == 'tool':
            name = id_to_name.get(m.get('tool_call_id', ''), '')
            if not name:
                # No matching assistant turn — drop rather than send a
                # functionResponse Gemini cannot pair.
                continue
            contents.append({
                'role':  'user',
                'parts': [{
                    'functionResponse': {
                        'name':     name,
                        'response': _tool_response(content),
                    },
                }],
            })

    return '\n\n'.join(system_chunks), contents


def _tool_response(content: str) -> dict:
    """Gemini requires an object; the transcript carries a JSON string."""
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return {'content': content}


def _clean_schema(schema):
    """Recursively drop keys Gemini's Schema object rejects."""
    if isinstance(schema, dict):
        out = {}
        for k, v in schema.items():
            if k in _SCHEMA_DROP:
                continue
            out[k] = _clean_schema(v)
        return out
    if isinstance(schema, list):
        return [_clean_schema(v) for v in schema]
    return schema


# ----------------------------------------------------------------------
# Response parsing
# ----------------------------------------------------------------------

_FINISH = {
    'STOP':       'end_turn',
    'MAX_TOKENS': 'max_tokens',
    'SAFETY':     'safety',
    'RECITATION': 'recitation',
    'OTHER':      'end_turn',
}


def _parse_candidate(data):
    """Return (text, tool_calls, stop_reason) for one response chunk."""
    candidates = data.get('candidates') or []
    if not candidates:
        return '', [], 'end_turn'

    cand = candidates[0]
    content = cand.get('content') or {}
    parts = content.get('parts') or []

    text = ''
    tool_calls = []
    for part in parts:
        if part.get('thought'):
            # Thinking-model reasoning part; not the final answer.
            continue
        if 'text' in part:
            text += part['text'] or ''
        elif 'functionCall' in part:
            fc = part['functionCall'] or {}
            tool_calls.append(ToolCall(
                # Gemini has no call id; synthesise a stable one so
                # the loop's id-based pairing keeps working.
                id=f'gemini-call-{len(tool_calls)}',
                name=fc.get('name', ''),
                arguments=fc.get('args') or {},
            ))

    reason = _FINISH.get(cand.get('finishReason', ''), 'end_turn')
    return text, tool_calls, reason


def _usage(data) -> dict:
    meta = data.get('usageMetadata') or {}
    out = {}
    if 'promptTokenCount' in meta:
        out['input_tokens'] = meta['promptTokenCount']
    if 'candidatesTokenCount' in meta:
        out['output_tokens'] = meta['candidatesTokenCount']
    return out