"""Approval gate.

Two states in this module plus the third that lives in the
dispatcher:

    REQUIRED     — the tool is T3; approval is required
    GRANTED      — the operator typed the confirmation word
    (NONE)       — the caller did not ask for approval

The console loop transitions REQUIRED → GRANTED by calling
`request_approval()`. The dispatcher refuses any T3 call
whose approval is not GRANTED.

T3 confirmation rules, per tool:

    kill_beacon        operator types the exact beacon ID
    killall_beacons    operator types "yes" AND the match count
    run_bof            operator types "yes"
    creds_reveal       operator types "yes"
    creds_add          operator types "yes"
    creds_validate     operator types "yes"
    download/upload    operator types "yes"
    screenshot_beacon  operator types "yes"

The `killall_beacons` two-part confirmation exists because
`killall` is the one tool that can end the engagement for
multiple hosts in one call. A single "yes" is too easy to type.
"""

from __future__ import annotations

import enum
import sys


class ApprovalState(enum.Enum):
    NONE         = 'none'
    PROMPT       = 'prompt'
    PREAPPROVED  = 'preapproved'


_CONFIRM_WORD = {
    # tool name -> callable that returns the expected word(s)
    'kill_beacon':     lambda a: str(a.get('beacon_id', '')),
    'killall_beacons': lambda a: 'yes',
    'run_bof':         lambda a: 'yes',
    'creds_reveal':    lambda a: 'yes',
    'creds_add':       lambda a: 'yes',
    'creds_validate':  lambda a: 'yes',
    'download_beacon_file': lambda a: 'yes',
    'upload_beacon_file':   lambda a: 'yes',
    'screenshot_beacon':    lambda a: 'yes',
}


def _describe(name: str, args: dict,
              match_count: int | None = None) -> list[str]:
    """Human-readable lines the operator reads before
    confirming. Not a table — sequential, because that is what
    the operator scans.
    """
    lines = []
    if name == 'kill_beacon':
        lines.append(f'Kill beacon #{args.get("beacon_id")}.')
        lines.append('The beacon receives a self-destruct task '
                     'on its next poll.')
        lines.append('This cannot be undone.')
    elif name == 'killall_beacons':
        scope = args.get('scope')
        lines.append(f'Queue kill on scope={scope!r}.')
        if scope == 'tag':
            lines.append(f'  tag: {args.get("tag")}')
        if scope == 'ids':
            lines.append(f'  ids: {args.get("ids")}')
        if match_count is not None:
            lines.append(f'  matches: {match_count} beacon(s)')
        lines.append('Every matching beacon receives a '
                     'self-destruct task on its next poll.')
        lines.append('This cannot be undone.')
    elif name == 'run_bof':
        lines.append(
            f'Run BOF {args.get("name")!r} on '
            f'#{args.get("beacon_id")}.')
        if args.get('args'):
            lines.append(f'  args: {args.get("args")}')
        lines.append('The BOF executes in-process on the target.')
    elif name == 'creds_reveal':
        lines.append(
            f'Reveal credential {args.get("id")!r}.')
        lines.append('The value will appear in your terminal '
                     'and in the transcript.')
    elif name == 'creds_add':
        lines.append(
            f'Store credential for user '
            f'{args.get("user")!r} '
            f'(kind={args.get("kind")}).')
        lines.append('The value is stored in the vault; it '
                     'does NOT appear in the audit chain.')
    elif name == 'creds_validate':
        lines.append(
            f'Validate credential {args.get("id")!r} from '
            f'beacon #{args.get("from_beacon")}.')
        lines.append('This attempts one bind. A failed bind '
                     'counts against the target account\'s '
                     'lockout policy.')
    elif name == 'download_beacon_file':
        lines.append(
            f'Download {args.get("remote_path")!r} from '
            f'#{args.get("beacon_id")}.')
        lines.append('The file is pushed to the loot store.')
    elif name == 'upload_beacon_file':
        lines.append(
            f'Upload {args.get("local_path")!r} to '
            f'{args.get("remote_path")!r} on '
            f'#{args.get("beacon_id")}.')
    elif name == 'screenshot_beacon':
        lines.append(
            f'Capture the desktop of '
            f'#{args.get("beacon_id")}.')
        lines.append('The PNG is saved locally.')
    return lines


def request_approval(name: str, args: dict,
                     *, match_count: int | None = None) -> bool:
    """Prompt the operator. Returns True if approved.

    Synchronous. The console loop calls this from a worker
    thread, so blocking stdin reads are fine.

    No timeout, no default-yes, no skip flag. Ctrl+C aborts.
    EOF aborts.
    """
    expected_fn = _CONFIRM_WORD.get(name, lambda a: 'yes')
    expected = expected_fn(args)

    if name == 'killall_beacons' and match_count is None:
        match_count = len(args.get('ids') or []) or None

    print()
    print('─' * 62)
    print(f'  APPROVAL REQUIRED  ·  {name}')
    print('─' * 62)
    for line in _describe(name, args, match_count=match_count):
        print(f'  {line}')
    print('─' * 62)

    if name == 'killall_beacons':
        # Two-part: yes, then the match count. The count
        # comes from the AI's own reasoning, so a typo in the
        # scope cannot be confirmed blindly.
        try:
            sys.stdout.write('  type "yes" to proceed: ')
            sys.stdout.flush()
            answer = sys.stdin.readline().strip().lower()
            if answer != 'yes':
                print('  ✗ declined')
                return False
            if match_count is None:
                print('  ✗ cannot confirm: match count is '
                      'unknown')
                return False
            sys.stdout.write(
                f'  type the match count ({match_count}) '
                f'to confirm: ')
            sys.stdout.flush()
            count = sys.stdin.readline().strip()
            if count != str(match_count):
                print('  ✗ count mismatch — declined')
                return False
        except (EOFError, KeyboardInterrupt):
            print()
            print('  ✗ aborted')
            return False
    else:
        try:
            sys.stdout.write(
                f'  type {expected!r} to confirm, anything '
                f'else to decline: ')
            sys.stdout.flush()
            answer = sys.stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print('  ✗ aborted')
            return False
        if answer.lower() != expected.lower():
            print('  ✗ declined')
            return False

    print('  ✓ approved')
    return True