"""Context window management.

The agent loop grows the conversation with each tool call.
Left alone, a long session overflows the model's context
window and the provider returns a 400 that surfaces as an
opaque error. This module prevents that by:

  1. Tracking an approximate token count.
  2. Compacting older turns into a summary when the count
     crosses a threshold.
  3. Refusing to proceed if compaction alone cannot fit the
     current turn — the operator gets a clear message
     instead of a provider error.

The token counter is a rough approximation: 1 token ≈ 4 chars
for English, 1 token ≈ 2 chars for JSON. This is close
enough for a compaction threshold that fires well below the
provider's actual limit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


_CPT_TEXT = 4
_CPT_JSON = 2
_CPT_TOOL = 1.5


def count_tokens(message: dict) -> int:
    content = message.get('content') or ''
    if isinstance(content, list):
        return sum(
            count_tokens({'role': 'tool',
                          'content': json.dumps(c, default=str)})
            for c in content)
    if not isinstance(content, str):
        content = json.dumps(content, default=str)
    chars = len(content)
    if message.get('tool_calls'):
        chars += len(json.dumps(
            message['tool_calls'], default=str))
        return chars // _CPT_JSON
    # Tool messages carry JSON payloads, and frequently
    # base64 blobs (loot downloads, file uploads) that
    # tokenizers handle at ~1.5 chars/token.
    if message.get('role') == 'tool':
        return max(1, int(chars / _CPT_TOOL))
    return max(1, chars // _CPT_TEXT)


def total_tokens(messages) -> int:
    return sum(count_tokens(m) for m in messages)


@dataclass
class CompactionResult:
    messages:  list
    dropped:   int
    summary:   str


def compact(messages: list, budget: int) -> CompactionResult:
    """Compact `messages` so it fits in `budget` tokens.

    Strategy: keep the first user message (the operator's
    original intent), the most recent complete turns, and
    replace the middle with a one-paragraph summary written from
    the audit IDs of the dropped tools.

    A "turn group" is a non-tool message plus the tool results
    that immediately follow it. Groups are kept or dropped
    whole, so an assistant tool call is never separated from
    its tool result. The newest group is always kept even when
    it alone is large; if the result still exceeds the budget,
    compaction fails with ContextOverflowError rather than
    handing the provider an invalid transcript.

    The summary is deterministic — it does not call the model
    (which would be a second provider round-trip inside a
    turn). It names every tool call made and every audit ID
    returned, so a dropped turn is still legible from the
    summary.
    """
    if total_tokens(messages) <= budget:
        return CompactionResult(messages, 0, '')

    # First message is the operator's intent. Keep it.
    head = messages[:1] if messages else []
    rest = messages[1:]
    groups = _groups(rest)

    # Newest group is kept unconditionally. Older groups are
    # added newest-first while the 70% soft budget allows.
    kept_groups = []
    used = sum(count_tokens(m) for m in head)
    for idx in range(len(groups) - 1, -1, -1):
        group = groups[idx]
        size = sum(count_tokens(m) for m in group)
        if kept_groups and used + size > budget * 0.7:
            break
        kept_groups.append(group)
        used += size
    kept_groups.reverse()
    keep = [m for g in kept_groups for m in g]
    dropped = [m for g in groups[:len(groups) - len(kept_groups)]
               for m in g]

    # Summarize dropped turns.
    calls = []
    audit_ids = []
    for m in dropped:
        for tc in (m.get('tool_calls') or []):
            calls.append(tc.get('name', '?'))
        content = m.get('content') or ''
        if isinstance(content, str) and 'audit_id' in content:
            try:
                d = json.loads(content)
                if d.get('audit_id'):
                    audit_ids.append(d['audit_id'])
            except Exception:
                pass

    summary = (
        f'[compacted {len(dropped)} earlier messages; '
        f'tools called: {", ".join(calls) or "none"}; '
        f'audit ids: {", ".join(audit_ids) or "none"}]'
    )
    rebuilt = head + [{'role': 'user',
                       'content': summary}] + keep
    if total_tokens(rebuilt) > budget:
        from .. import errors
        raise errors.ContextOverflowError(
            f'compaction could not fit transcript in '
            f'{budget} tokens (got {total_tokens(rebuilt)}); '
            f'type `reset` to clear the transcript')
    return CompactionResult(rebuilt, len(dropped), summary)


def _groups(messages: list) -> list[list]:
    """Split a message list into complete turn groups.

    A group starts at any non-tool message and includes every
    tool message immediately after it. Tool messages at the
    very start (already orphaned) form their own group so they
    are never mixed into a later turn.
    """
    groups: list[list] = []
    for m in messages:
        if not groups or m.get('role') != 'tool':
            groups.append([m])
        else:
            groups[-1].append(m)
    return groups