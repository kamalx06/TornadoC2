"""Agent loop.

One operator turn is one question, N tool calls, and a final
response. The loop:

  1. Reads the operator's question.
  2. Sends it plus the tool catalogue to the provider.
  3. While the provider asks for tool calls:
       a. Compact the context if it exceeds the window.
       b. Prompt for approval if the tool is T3.
       c. Dispatch the tool, append the result.
       d. Send the updated transcript back to the provider.
  4. Print the provider's final assistant message.
  5. Return to the prompt.

Ctrl+C during a turn cancels the in-flight provider call and
returns to the prompt without exiting. Ctrl+D at the prompt
exits.

Three entry points:

  run_console_from_path(cfg_path, cfg)   load a fresh client,
                                         then run the console.
                                         Used by
                                         `beacon-client.py ai`.

  run_console(cfg, client)               interactive console
                                         against an already-
                                         loaded client. Used by
                                         the REPL's `ai` command.

  run_one_shot(cfg, client, question)    one turn against an
                                         already-loaded client.
                                         Used by the REPL's
                                         `ai <question>` form.
"""

from __future__ import annotations

import asyncio
import json
import sys

from .. import errors, logging
from ..adapter import ClientAdapter
from ..approval import ApprovalState, request_approval
from ..config import AiConfig, load_client_for_mcp
from ..dispatch import dispatch
from ..providers import build_provider
from ..tools import TOOLS, requires_approval
from .context import compact, total_tokens
from .prompt import SYSTEM


def _tool_specs(capabilities: frozenset) -> list:
    out = []
    for t in TOOLS:
        cap = t.get('capability')
        if cap and cap not in capabilities:
            continue
        tier = 'T3 (requires operator approval)' \
               if requires_approval(t['name']) else 'T1/T2'
        out.append({
            'name':         t['name'],
            'description':  f'[{tier}] {t["description"]}',
            'input_schema': t['input_schema'],
        })
    return out


def _print(msg: str = '', *, dim: bool = False):
    if dim:
        sys.stdout.write(f'\033[2m{msg}\033[0m\n')
    else:
        sys.stdout.write(msg + '\n')
    sys.stdout.flush()


def _banner(cfg: AiConfig, client: ClientAdapter) -> None:
    identity = client.identity or {}
    name = identity.get('name', '?')
    role = identity.get('role', '?')

    _print('TornadoC2 AI console')
    _print(f'  operator : {name} ({role})', dim=True)
    _print(f'  provider : {cfg.provider} / {cfg.model}', dim=True)
    _print(f'  verbs    : {len(cfg.mcp_allow_verbs)} allowed', dim=True)
    _print(f'  bofs     : {len(cfg.mcp_allow_bofs)} allowed', dim=True)
    _print(f'  approval : T3 tools prompt before dispatch', dim=True)
    _print()


def _build_provider(cfg: AiConfig):
    """Build a provider, or return None after printing the error."""
    try:
        return build_provider({
            'provider':    cfg.provider,
            'model':       cfg.model,
            'api_key':     cfg.api_key,
            'base_url':    cfg.base_url,
            'temperature': cfg.temperature,
        })
    except errors.ProviderNotConfiguredError as exc:
        _print(f'[ai] {exc}', dim=True)
        if exc.hint:
            _print(f'     {exc.hint}', dim=True)
        return None


# ---------------------------------------------------------------------
# Entry point 1 — a separate process with its own TLS session.

async def run_console_from_path(cfg_path, cfg: AiConfig) -> int:
    """Load a fresh client from a .cfg, then run the console.

    This is the entry point `beacon-client.py ai` uses. It
    creates its own TLS session and its own Console — the
    operator is opening the AI console as a standalone
    program, not augmenting an existing REPL session.
    """
    try:
        client = await load_client_for_mcp(cfg_path)
    except errors.McpError as exc:
        _print(f'[ai] {exc}', dim=True)
        if exc.hint:
            _print(f'     {exc.hint}', dim=True)
        return 1
    return await run_console(cfg, client)


# ---------------------------------------------------------------------
# Entry point 2 — an already-loaded client, from the REPL.

async def run_console(cfg: AiConfig, client: ClientAdapter) -> int:
    """Interactive AI console against a pre-loaded client.

    Shares the operator's existing authenticated `Client` —
    no re-auth, no second TLS handshake. When the operator
    types `exit`, control returns to the caller (the REPL's
    `_cmd_ai`), which returns to the `adc >` prompt.
    """
    provider = _build_provider(cfg)
    if provider is None:
        return 1

    _banner(cfg, client)

    if not provider.supports_tools:
        _print(f'[ai] {cfg.provider} does not support tool '
               f'calling; running in synthesis-only mode.',
               dim=True)
        await _synthesis_mode(client, provider, cfg)
        return 0

    tools = _tool_specs(client.capabilities)
    transcript: list = []

    while True:
        try:
            sys.stdout.write('\n› ')
            sys.stdout.flush()
            line = sys.stdin.readline()
        except (EOFError, KeyboardInterrupt):
            _print()
            break
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        if line in ('exit', 'quit', ':q'):
            break
        if line == 'reset':
            transcript = []
            _print('[ai] transcript cleared', dim=True)
            continue
        if line == 'tokens':
            _print(f'[ai] transcript ≈ '
                   f'{total_tokens(transcript)} tokens '
                   f'({len(transcript)} messages)', dim=True)
            continue

        try:
            await _turn(
                client, provider, cfg, tools,
                transcript, line)
        except KeyboardInterrupt:
            _print()
            _print('[ai] turn cancelled', dim=True)
        except errors.ProviderError as exc:
            _print(f'[ai] provider error: {exc}', dim=True)
            if exc.hint:
                _print(f'     {exc.hint}', dim=True)
        except Exception as exc:
            logging.error('console.turn_failed',
                          err=f'{type(exc).__name__}: {exc}')
            _print(f'[ai] {type(exc).__name__}: {exc}', dim=True)

    return 0


# ---------------------------------------------------------------------
# Entry point 3 — a single turn, from the REPL.

async def run_one_shot(cfg: AiConfig, client: ClientAdapter,
                       question: str) -> int:
    """One turn against a pre-loaded client.

    Used by the REPL's `ai <question>` form. No banner, no
    prompt, no transcript carried between calls — one
    question, one answer, back to the REPL. The absence of
    a persistent transcript is deliberate: a one-shot
    question has no follow-up, and keeping the transcript
    would blur the line between "asked a question" and
    "opened the console".
    """
    provider = _build_provider(cfg)
    if provider is None:
        return 1

    if not provider.supports_tools:
        _print(f'[ai] {cfg.provider} does not support tool '
               f'calling; one-shot mode is unavailable for '
               f'this provider', dim=True)
        return 1

    tools = _tool_specs(client.capabilities)
    transcript: list = []
    try:
        await _turn(
            client, provider, cfg, tools,
            transcript, question)
    except KeyboardInterrupt:
        _print()
        _print('[ai] turn cancelled', dim=True)
        return 1
    except errors.ProviderError as exc:
        _print(f'[ai] provider error: {exc}', dim=True)
        if exc.hint:
            _print(f'     {exc.hint}', dim=True)
        return 1
    except Exception as exc:
        logging.error('console.one_shot_failed',
                      err=f'{type(exc).__name__}: {exc}')
        _print(f'[ai] {type(exc).__name__}: {exc}', dim=True)
        return 1
    return 0


# ---------------------------------------------------------------------
# The turn loop — unchanged from the previous version.

async def _turn(client, provider, cfg, tools,
                transcript: list, question: str):
    transcript.append({'role': 'user', 'content': question})

    for turn in range(cfg.max_turns):
        # --- Compact before the provider call -----------------
        compaction = compact(
            transcript, cfg.max_context_tokens)
        if compaction.dropped:
            compacted = compaction.messages
            transcript.clear()
            transcript.extend(compacted)
            logging.info(
                'console.compacted',
                dropped=compaction.dropped)

        # --- Ask the provider ---------------------------------
        response = await provider.chat(
            _normalize(transcript, provider.name),
            tools=tools,
            system=SYSTEM,
            max_tokens=cfg.max_tokens,
        )

        if response.content:
            _print()
            _print(response.content)

        if not response.tool_calls:
            transcript.append({
                'role':    'assistant',
                'content': response.content or '',
            })
            return

        # --- Append the assistant turn ------------------------
        transcript.append({
            'role':       'assistant',
            'content':    response.content or '',
            'tool_calls': [
                {'id': tc.id, 'name': tc.name,
                 'arguments': tc.arguments}
                for tc in response.tool_calls
            ],
        })

        # --- Budget exhausted: synthesise paired tool results
        # so the transcript stays coherent (every tool_call has
        # a matching tool_result), then raise.
        if turn == cfg.max_turns - 1:
            for tc in response.tool_calls:
                transcript.append({
                    'role':         'tool',
                    'tool_call_id': tc.id,
                    'content': json.dumps({
                        'ok':       False,
                        'error':    'tool_call_budget_exhausted: '
                                    'the model kept requesting '
                                    'tools without a final answer',
                        'audit_id': None,
                    }),
                })
            raise errors.ServerError(
                f'turn exceeded max_turns={cfg.max_turns}; '
                f'the model kept asking for tools without '
                f'producing a final answer')

        # --- Handle each tool call ----------------------------
        for tc in response.tool_calls:
            _print()
            _print(f'› {tc.name}'
                   f'({json.dumps(tc.arguments, default=str)})',
                   dim=True)

            approval = ApprovalState.PREAPPROVED
            if requires_approval(tc.name):
                match_count = None
                if tc.name == 'killall_beacons':
                    try:
                        match_count = await _killall_match_count(
                            client, tc.arguments)
                    except Exception as exc:
                        _print(f'  ✗ could not resolve kill match '
                               f'count: {exc}', dim=True)
                        transcript.append({
                            'role':         'tool',
                            'tool_call_id': tc.id,
                            'content': json.dumps({
                                'ok':       False,
                                'error':    'killall_match_count_failed: '
                                            f'{type(exc).__name__}: '
                                            f'{exc}',
                                'audit_id': None,
                            }),
                        })
                        continue
                ok = request_approval(
                    tc.name, tc.arguments,
                    match_count=match_count)
                if not ok:
                    result = {
                        'ok':       False,
                        'error':    'operator_declined: '
                                    'approval was not granted',
                        'audit_id': None,
                    }
                    transcript.append({
                        'role':         'tool',
                        'tool_call_id': tc.id,
                        'content':      json.dumps(result),
                    })
                    continue

            try:
                result = await dispatch(
                    tc.name, tc.arguments, client, cfg,
                    approval=approval,
                )
            except Exception as exc:
                logging.error(
                    'console.dispatch_failed',
                    tool=tc.name,
                    err=f'{type(exc).__name__}: {exc}')
                payload = json.dumps({
                    'ok':       False,
                    'error':    f'{type(exc).__name__}: {exc}',
                    'audit_id': None,
                })
                transcript.append({
                    'role':         'tool',
                    'tool_call_id': tc.id,
                    'content':      payload,
                })
                _print(f'  ✗ {type(exc).__name__}: {exc}',
                       dim=True)
                continue

            full = json.dumps(result.to_dict(), default=str)
            if len(full) > 60_000:
                payload = json.dumps({
                    'ok':        getattr(result, 'ok', None),
                    'truncated': True,
                    'note':      'result truncated to 60K chars',
                    'payload':   full[:60_000],
                }, default=str)
            else:
                payload = full
            transcript.append({
                'role':         'tool',
                'tool_call_id': tc.id,
                'content':      payload,
            })
            _print(f'  ✓ {result.elapsed_ms:.0f} ms',
                   dim=True)

    raise errors.ServerError(
        f'turn exceeded max_turns={cfg.max_turns}; '
        f'the model kept asking for tools without '
        f'producing a final answer')


async def _killall_match_count(client, args: dict) -> int:
    """Resolve how many beacons a killall would match.

    The approval prompt needs the real count, not just the
    length of an explicit `ids` list. Read the same engagement
    listing the handler will act on.
    """
    scope = str(args.get('scope') or '').lower()
    if scope == 'ids':
        return len(args.get('ids') or [])
    rows = await client.list_beacons()
    if scope == 'all':
        return len(rows or [])
    if scope == 'stale':
        return len([b for b in (rows or [])
                    if not b.get('alive')])
    if scope == 'tag':
        tag = str(args.get('tag') or '')
        return len([b for b in (rows or [])
                    if tag in (b.get('tags') or [])])
    return 0


def _normalize(messages: list, provider_name: str) -> list:
    if provider_name == 'anthropic':
        return _to_anthropic(messages)
    if provider_name in ('openai', 'openrouter', 'ollama'):
        return _to_openai(messages)
    return messages


def _to_openai(messages: list) -> list:
    """Convert the internal transcript to Chat Completions wire
    format.

    The internal assistant turn stores tool calls as
    `{id, name, arguments}`. OpenAI-compatible APIs expect
    `{id, type: 'function', function: {name, arguments}}` with
    arguments as a JSON string, and tool results as
    `{role: 'tool', tool_call_id, content}`.
    """
    out = []
    for m in messages:
        role = m.get('role', 'user')
        if role == 'assistant':
            msg = {
                'role':    'assistant',
                'content': m.get('content') or '',
            }
            calls = []
            for tc in (m.get('tool_calls') or []):
                args = tc.get('arguments')
                if not isinstance(args, str):
                    args = json.dumps(args or {}, default=str)
                calls.append({
                    'id':   tc.get('id', ''),
                    'type': 'function',
                    'function': {
                        'name':      tc.get('name', ''),
                        'arguments': args,
                    },
                })
            if calls:
                msg['tool_calls'] = calls
            out.append(msg)
        elif role == 'tool':
            out.append({
                'role':         'tool',
                'tool_call_id': m.get('tool_call_id', ''),
                'content':      m.get('content', ''),
            })
        else:
            out.append({
                'role':    role,
                'content': m.get('content', ''),
            })
    return out


def _to_anthropic(messages: list) -> list:
    out = []
    for m in messages:
        role = m.get('role', 'user')
        if role == 'system':
            out.append({
                'role': 'user',
                'content': m.get('content', ''),
            })
            continue
        if role == 'tool':
            out.append({
                'role': 'user',
                'content': [{
                    'type':        'tool_result',
                    'tool_use_id': m.get('tool_call_id', ''),
                    'content':     m.get('content', ''),
                }],
            })
        elif role == 'assistant':
            blocks = []
            if m.get('content'):
                blocks.append({
                    'type': 'text',
                    'text': m['content'],
                })
            for tc in (m.get('tool_calls') or []):
                blocks.append({
                    'type':  'tool_use',
                    'id':    tc['id'],
                    'name':  tc['name'],
                    'input': tc['arguments'],
                })
            out.append({'role': 'assistant', 'content': blocks})
        else:
            out.append({
                'role':    role,
                'content': m.get('content', ''),
            })
    return out


async def _synthesis_mode(client, provider, cfg):
    """Claude Code path — no tool calls, one prompt."""
    try:
        beacons = await client.list_beacons()
        notes = await client.notes('list')
    except Exception as exc:
        _print(f'[ai] context load failed: {exc}', dim=True)
        return
    prompt = (
        f'Engagement state:\n'
        f'{json.dumps(beacons, indent=2, default=str)}\n\n'
        f'Engagement notes:\n'
        f'{json.dumps(notes, indent=2, default=str)}\n\n'
        f'Summarise the state of this engagement. What is on '
        f'it, what has already been done, and what is the '
        f'operator likely to want next?')
    _print()
    response = await provider.chat(
        [{'role': 'user', 'content': prompt}])
    _print(response.content)