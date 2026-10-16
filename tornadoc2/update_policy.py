"""Official repository and branch policy for secure self-updates."""

import os
import re
from urllib.parse import urlparse

OFFICIAL_REPO_OWNER = 'kamalx06'
OFFICIAL_REPO_NAME = 'TornadoC2'
OFFICIAL_REPO_URL = 'https://github.com/kamalx06/TornadoC2/'
OFFICIAL_BRANCH = 'main'

OFFICIAL_SSH_REMOTE = (
    f'git@github.com:{OFFICIAL_REPO_OWNER}/{OFFICIAL_REPO_NAME}.git'
)
OFFICIAL_SSH_REMOTE_ALT = (
    f'ssh://git@github.com/{OFFICIAL_REPO_OWNER}/{OFFICIAL_REPO_NAME}.git'
)


def parse_remote_url(url):
    if not url:
        return None
    url = url.strip()
    if not url:
        return None

    scp_match = re.match(
        r'^(?:ssh://)?(?:git@)?([^:/]+):([^/]+)/(.+?)(?:\.git)?/?$',
        url,
    )
    if scp_match and '@' in url.split(':')[0]:
        host, owner, repo = scp_match.groups()
        return (host.lower(), owner.lower(),
                repo.removesuffix('.git').lower())

    if url.startswith('ssh://'):
        parsed = urlparse(url)
        path = parsed.path.lstrip('/')
        parts = path.split('/')
        if len(parts) >= 2 and parsed.hostname:
            owner, repo = parts[0], parts[1]
            return (parsed.hostname.lower(), owner.lower(),
                    repo.removesuffix('.git').lower())
        return None

    if '://' in url:
        parsed = urlparse(url)
        if not parsed.hostname:
            return None
        path = parsed.path.lstrip('/')
        parts = path.split('/')
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            return (parsed.hostname.lower(), owner.lower(),
                    repo.removesuffix('.git').lower())
        return None

    return None


def is_official_remote(url):
    parsed = parse_remote_url(url)
    if not parsed:
        return False
    host, owner, repo = parsed
    if host != 'github.com':
        return False
    return (owner == OFFICIAL_REPO_OWNER.lower()
            and repo == OFFICIAL_REPO_NAME.lower())


def get_origin_url(repo_root, run_git):
    result = run_git('remote', 'get-url', 'origin', cwd=repo_root)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def verify_origin_remote(repo_root, run_git):
    actual = get_origin_url(repo_root, run_git)
    if not actual:
        return False, OFFICIAL_REPO_URL.rstrip('/'), ''
    ok = is_official_remote(actual)
    expected = OFFICIAL_REPO_URL.rstrip('/')
    return ok, expected, actual


def get_current_branch(repo_root, run_git):
    result = run_git('rev-parse', '--abbrev-ref', 'HEAD', cwd=repo_root)
    if result.returncode != 0:
        return None
    branch = result.stdout.strip()
    if branch == 'HEAD':
        return None
    return branch


def verify_trusted_branch(repo_root, run_git):
    branch = get_current_branch(repo_root, run_git)
    if not branch:
        return False, branch or 'HEAD'
    return branch == OFFICIAL_BRANCH, branch


def check_working_tree(repo_root, run_git):
    """Inspect the working tree for local modifications.

    Only tracked changes refuse the update. Untracked files are
    allowed — they are the runtime state the tool creates at first
    run (.keys/, logs/, team_ca/, mtls_certs/, ...) plus anything
    the operator has staged locally. Git's own fast-forward check
    refuses if an incoming commit would overwrite an untracked
    file, so this check does not need to duplicate that safety
    gate.

    Returns (clean, status_lines) where status_lines is the
    filtered porcelain output for tracked changes only.
    """
    result = run_git('status', '--porcelain', cwd=repo_root)
    if result.returncode != 0:
        return False, [result.stderr.strip() or 'git status failed']

    tracked_changes = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        if line.startswith('??'):
            continue
        tracked_changes.append(line)

    if tracked_changes:
        return False, tracked_changes

    git_dir_result = run_git('rev-parse', '--git-dir', cwd=repo_root)
    if git_dir_result.returncode != 0:
        return False, ['Unable to locate .git directory']
    git_dir = git_dir_result.stdout.strip()
    if not os.path.isabs(git_dir):
        git_dir = os.path.join(repo_root, git_dir)

    conflict_markers = (
        'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'BISECT_LOG',
    )
    for marker in conflict_markers:
        if os.path.exists(os.path.join(git_dir, marker)):
            return False, [
                f'Repository is in an incomplete '
                f'{marker.replace("_HEAD", "").lower()} state'
            ]

    rebase_dir = os.path.join(git_dir, 'rebase-merge')
    rebase_apply = os.path.join(git_dir, 'rebase-apply')
    if os.path.isdir(rebase_dir) or os.path.isdir(rebase_apply):
        return False, ['Repository is in the middle of a rebase']

    return True, []


_PORCELAIN_STATUS = {
    'M': 'modified', 'A': 'added', 'D': 'deleted',
    'R': 'renamed', 'C': 'copied', 'U': 'unmerged',
}


def _describe_porcelain_path(x, y, path):
    if x == '?' and y == '?':
        return f'untracked  {path}'
    if ' -> ' in path:
        return f'renamed    {path}'
    if x == 'D' or y == 'D':
        return f'deleted    {path}'
    if x == 'A' or y == 'A':
        return f'added      {path}'
    if x == 'M' or y == 'M':
        return f'modified   {path}'
    x_label = _PORCELAIN_STATUS.get(x)
    y_label = _PORCELAIN_STATUS.get(y)
    if x_label and y_label:
        return f'{x_label}/{y_label}  {path}'
    label = x_label or y_label or 'changed'
    return f'{label:<10} {path}'


def format_working_tree_changes(status_lines):
    formatted = []
    for line in status_lines:
        if len(line) >= 4 and line[2] == ' ':
            formatted.append(
                _describe_porcelain_path(line[0], line[1], line[3:])
            )
        elif line.strip():
            formatted.append(line.strip())
    return formatted


def get_trusted_branch_tip(repo_root, run_git):
    branch_ref = f'origin/{OFFICIAL_BRANCH}'
    result = run_git('rev-parse', branch_ref, cwd=repo_root)
    if result.returncode != 0:
        return None
    commit = result.stdout.strip()
    return commit or None