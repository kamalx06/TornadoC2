"""Claude Code CLI as a provider.

Claude Code (`claude` on PATH) runs one prompt and returns
text — it has no structured tool-calling protocol the way the
HTTP APIs do. It is useful in this framework for
**synthesis-only** questions ('what is on this engagement?',
'summarize what we know about dc01') where the operator wants
a narrative answer rather than an action.

It is not usable as the backend of the agent loop because the
loop needs structured tool calls. If it is selected,
`supports_tools` is False and the AI console refuses to enter
the agent loop; it runs one prompt and exits.
"""

import asyncio
import json
import shutil

from ..errors import ProviderError
from .base import Provider, ChatResponse, register


@register
class ClaudeCodeProvider(Provider):

    name = 'claude_code'
    supports_tools = False
    DEFAULT_MODEL = ''   # uses whatever `claude` defaults to

    async def chat(self, messages, tools=None, **kwargs):
        claude = shutil.which('claude')
        if not claude:
            raise ProviderError(
                'claude not found on PATH — install Claude Code '
                'or use a different provider in ai.json')

        # Concatenate the message history into one prompt.
        # Claude Code has no multi-turn protocol; everything is
        # in the prompt.
        parts = []
        for m in messages:
            role = m.get('role', 'user')
            content = m.get('content', '')
            if content:
                parts.append(f'[{role}]\n{content}')
        prompt = '\n\n'.join(parts)

        cmd = [claude, '-p', prompt, '--output-format', 'json']
        if self.model:
            cmd.extend(['--model', self.model])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(
            proc.communicate(), timeout=300)

        if proc.returncode != 0:
            raise ProviderError(
                f'claude exited {proc.returncode}: '
                f'{err.decode(errors="replace")[:500]}')

        try:
            data = json.loads(out.decode('utf-8'))
            content = data.get('result', '')
        except Exception:
            content = out.decode('utf-8', 'replace')

        return ChatResponse(
            content=content,
            tool_calls=[],
            stop_reason='end_turn',
            usage={},
        )