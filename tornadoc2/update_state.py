"""Persistent update state and rollback support."""

import json
import os
from datetime import datetime, timezone

try:
    from .constants import LOGS_DIR
except (ImportError, AttributeError):
    LOGS_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'logs',
    )

UPDATE_STATE_DIR = os.path.join(LOGS_DIR, '.update')
UPDATE_STATE_FILE = os.path.join(UPDATE_STATE_DIR, 'state.json')

STATE_IDLE = 'idle'
STATE_PREPARING = 'preparing'
STATE_APPLYING = 'applying'
STATE_VALIDATING = 'validating'
STATE_READY_TO_RESTART = 'ready-to-restart'
STATE_FAILED = 'failed'
STATE_ROLLING_BACK = 'rolling-back'
STATE_ROLLED_BACK = 'rolled-back'
STATE_COMPLETED = 'completed'


def _utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _ensure_state_dir():
    os.makedirs(UPDATE_STATE_DIR, exist_ok=True)


def load_state():
    if not os.path.isfile(UPDATE_STATE_FILE):
        return {'state': STATE_IDLE}
    try:
        with open(UPDATE_STATE_FILE, 'r', encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {'state': STATE_IDLE, 'corrupt': True}


def save_state(data):
    _ensure_state_dir()
    payload = dict(data)
    payload['updated_at'] = _utc_now()
    temp_path = UPDATE_STATE_FILE + '.tmp'
    with open(temp_path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write('\n')
    os.replace(temp_path, UPDATE_STATE_FILE)


def begin_update(previous_revision, target_revision, repository, branch):
    save_state({
        'state': STATE_PREPARING,
        'started_at': _utc_now(),
        'previous_revision': previous_revision,
        'target_revision': target_revision,
        'repository': repository,
        'trusted_branch': branch,
    })


def set_state(state, **extra):
    current = load_state()
    current['state'] = state
    current.update(extra)
    save_state(current)


def clear_state():
    save_state({'state': STATE_IDLE})


def is_interrupted_state(state):
    return state.get('state') in {
        STATE_PREPARING, STATE_APPLYING, STATE_VALIDATING,
        STATE_READY_TO_RESTART, STATE_ROLLING_BACK,
    }


def rollback_to_revision(repo_root, previous_revision, run_git):
    """Restore a previous revision without destructive clean/reset --hard."""
    if not previous_revision:
        return False, 'Missing previous revision for rollback'

    reset = run_git('reset', '--mixed', previous_revision, cwd=repo_root)
    if reset.returncode != 0:
        return False, (
            reset.stderr or reset.stdout or 'git reset failed'
        ).strip()

    restore = run_git('checkout', '--', '.', cwd=repo_root)
    if restore.returncode != 0:
        return False, (
            restore.stderr or restore.stdout or 'git checkout failed'
        ).strip()

    verify = run_git('rev-parse', 'HEAD', cwd=repo_root)
    if verify.returncode != 0:
        return False, 'Unable to verify rollback revision'
    if verify.stdout.strip() != previous_revision:
        return False, 'Rollback did not restore the expected revision'
    return True, ''