"""Self-update from the official TornadoC2 Git repository.

The updater always fetches directly from the official repository
URL, regardless of how the local installation's Git remotes are
configured. Community forks therefore keep receiving updates from
the official project without needing to add an ``upstream``
remote or rename ``origin``.
"""

import os
import shutil
import subprocess
import sys

from .update_audit import UpdateAuditLogger
from .update_lock import UpdateLock, UpdateLockError
from .update_policy import (
    OFFICIAL_BRANCH,
    OFFICIAL_REPO_URL,
    check_working_tree,
    format_working_tree_changes,
    verify_trusted_branch,
)
from .update_state import (
    STATE_APPLYING,
    STATE_COMPLETED,
    STATE_FAILED,
    STATE_ROLLED_BACK,
    STATE_ROLLING_BACK,
    STATE_VALIDATING,
    begin_update,
    clear_state,
    is_interrupted_state,
    load_state,
    rollback_to_revision,
    set_state,
)
from .update_validate import validate_installation

OFFICIAL_REPO_URL = OFFICIAL_REPO_URL
OFFICIAL_FETCH_REF = 'refs/tornadoc2/upstream'

GIT_TIMEOUT_QUICK = 30
GIT_TIMEOUT_FETCH = 120
GIT_TIMEOUT_APPLY = 180

GIT_NOT_AVAILABLE_MSG = (
    'Git is not available on this system. Please install Git or '
    f'manually check for updates from {OFFICIAL_REPO_URL}'
)
NOT_GIT_REPO_MSG = (
    'This TornadoC2 installation is not a Git repository. '
    f'Please update manually from {OFFICIAL_REPO_URL}'
)
UP_TO_DATE_MSG = 'TornadoC2 is already running the latest version.'
UPDATE_SUCCESS_MSG = 'Update installed successfully. Restarting TornadoC2...'

WRONG_BRANCH_MSG = (
    'Updates are only permitted from the trusted branch {branch}.\n'
    'Current branch: {current}\n\n'
    'Update aborted for security reasons.'
)
DIRTY_TREE_HEADER = (
    'Update aborted: the installation has uncommitted local changes.\n\n'
    'Updates require a clean working tree.'
)
DIRTY_TREE_FOOTER = (
    '\nDiscard or stash your changes, then run update again:\n'
    '  git stash push -u -m "local changes"\n'
    '  git checkout -- .'
)
INTERRUPTED_UPDATE_MSG = (
    'A previous update did not complete successfully.\n'
    'Recorded state: {state}\n'
    'Previous revision: {previous}\n'
    'Target revision: {target}\n\n'
    'Resolve the repository state manually or retry the update '
    'after inspection.'
)
DIVERGED_FORK_HEADER = (
    'This installation has local commits that are not in the '
    'official branch.\nA fast-forward update cannot be applied '
    'on top of them.'
)
DIVERGED_FORK_PROMPT = (
    "To update anyway, the local branch must be reset to the "
    "official revision.\n"
    "This will PERMANENTLY DISCARD local commits that are not in "
    "the official\nbranch. Uncommitted changes were already "
    "checked and are not present.\n\n"
    "If you want to keep your local commits, cancel now and rebase "
    "them manually:\n"
    f"  git rebase {OFFICIAL_FETCH_REF}\n\n"
    "Type 'reset' (without quotes) to discard local commits and "
    "continue, or\nanything else to cancel: "
)


def _install_root():
    return os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )


def _git_env():
    env = os.environ.copy()
    env['GIT_TERMINAL_PROMPT'] = '0'
    env['GIT_ASKPASS'] = ''
    env['SSH_ASKPASS'] = ''
    env['GCM_INTERACTIVE'] = 'Never'
    return env


def _run_git(*args, cwd, timeout=GIT_TIMEOUT_QUICK):
    try:
        return subprocess.run(
            ['git', *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_git_env(),
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout if isinstance(exc.stdout, str)
               else (exc.stdout or b'').decode('utf-8', errors='replace'))
        err = (exc.stderr if isinstance(exc.stderr, str)
               else (exc.stderr or b'').decode('utf-8', errors='replace'))
        return subprocess.CompletedProcess(
            args=['git', *args],
            returncode=-1,
            stdout=out or '',
            stderr=(err or f'Git command timed out after {timeout}s').strip(),
        )
    except OSError as exc:
        return subprocess.CompletedProcess(
            args=['git', *args],
            returncode=-1,
            stdout='',
            stderr=str(exc),
        )


def git_available():
    return shutil.which('git') is not None


def get_repo_root():
    install_root = _install_root()
    result = _run_git('rev-parse', '--show-toplevel', cwd=install_root)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def is_git_repo(cwd):
    result = _run_git(
        'rev-parse', '--is-inside-work-tree', cwd=cwd)
    return result.returncode == 0 and result.stdout.strip() == 'true'


def _git_error(result, fallback='Git command failed'):
    return (result.stderr or result.stdout or fallback).strip()


def _short_revision(revision):
    return revision[:7] if revision else 'unknown'


def _fetch_official_branch(repo_root):
    refspec = f'+refs/heads/{OFFICIAL_BRANCH}:{OFFICIAL_FETCH_REF}'
    return _run_git(
        'fetch', '--quiet', '--no-tags',
        OFFICIAL_REPO_URL, refspec,
        cwd=repo_root,
        timeout=GIT_TIMEOUT_FETCH,
    )


def _get_official_tip(repo_root):
    result = _run_git(
        'rev-parse', '--verify', OFFICIAL_FETCH_REF, cwd=repo_root)
    if result.returncode != 0:
        return None
    revision = result.stdout.strip()
    return revision or None


def _is_fast_forwardable(repo_root, target_revision):
    result = _run_git(
        'merge-base', '--is-ancestor', 'HEAD', target_revision,
        cwd=repo_root,
    )
    if result.returncode == 0:
        return 'yes', None
    if result.returncode == 1:
        return 'no', None
    return 'unknown', _git_error(
        result,
        'Unable to determine relationship with the official branch',
    )


def _collect_update_preview(repo_root, current_revision, target_revision):
    count_result = _run_git(
        'rev-list', '--count',
        f'{current_revision}..{target_revision}',
        cwd=repo_root,
    )
    commit_count = (
        count_result.stdout.strip()
        if count_result.returncode == 0 else '?'
    )

    log_result = _run_git(
        'log', '--oneline', '--no-decorate',
        f'{current_revision}..{target_revision}',
        cwd=repo_root,
        timeout=GIT_TIMEOUT_QUICK,
    )
    commits = []
    if log_result.returncode == 0:
        commits = log_result.stdout.strip().splitlines()[:10]

    stat_result = _run_git(
        'diff', '--shortstat', current_revision, target_revision,
        cwd=repo_root,
        timeout=GIT_TIMEOUT_QUICK,
    )
    shortstat = (
        stat_result.stdout.strip()
        if stat_result.returncode == 0 else ''
    )

    return commit_count, commits, shortstat


def _format_dirty_tree_message(status_lines):
    changes = format_working_tree_changes(status_lines)
    lines = [DIRTY_TREE_HEADER, '', 'Local changes:']
    for entry in changes[:20]:
        lines.append(f'  {entry}')
    if len(changes) > 20:
        lines.append(f'  ... and {len(changes) - 20} more')
    lines.append(DIRTY_TREE_FOOTER)
    return '\n'.join(lines)


def _restart_process():
    argv = [sys.executable, *sys.argv]
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == 'nt':
        subprocess.Popen(argv, close_fds=False)
        os._exit(0)
    os.execv(sys.executable, argv)


class Updater:
    def __init__(self, handler):
        self.h = handler
        self._busy = False
        self.audit = UpdateAuditLogger()
        self._run_git = _run_git

    def handle_command(self, cmd_parts):
        if not cmd_parts or cmd_parts[0].lower() != 'update':
            return False
        self.run_update()
        return True

    def _print_error(self, message):
        print(f"{self.h.colors['red']}{message}{self.h.colors['end']}")

    def _print_warning(self, message):
        print(f"{self.h.colors['yellow']}{message}{self.h.colors['end']}")

    def _print_info(self, message):
        print(f"{self.h.colors['cyan']}{message}{self.h.colors['end']}")

    def _print_success(self, message):
        print(f"{self.h.colors['green']}{message}{self.h.colors['end']}")

    def _report_interrupted_update(self):
        state = load_state()
        if not is_interrupted_state(state):
            return
        self._print_warning(
            INTERRUPTED_UPDATE_MSG.format(
                state=state.get('state', 'unknown'),
                previous=state.get('previous_revision', 'unknown'),
                target=state.get('target_revision', 'unknown'),
            )
        )
        self.audit.log(
            'UPDATE_INTERRUPTED_DETECTED',
            state=state.get('state'),
            previous_revision=state.get('previous_revision'),
            target_revision=state.get('target_revision'),
        )

    def run_update(self):
        if self._busy:
            self._print_warning('Update already in progress.')
            return

        colors = self.h.colors
        self._busy = True
        repo_root = None
        previous_revision = None
        target_revision = None
        operator_confirmed = 'no'

        try:
            with UpdateLock():
                self._report_interrupted_update()

                if not git_available():
                    self._print_warning(GIT_NOT_AVAILABLE_MSG)
                    self.audit.log(
                        'UPDATE_ABORTED', reason='git_unavailable')
                    return

                repo_root = get_repo_root()
                if not repo_root or not is_git_repo(repo_root):
                    self._print_warning(NOT_GIT_REPO_MSG)
                    self.audit.log(
                        'UPDATE_ABORTED', reason='not_git_repo')
                    return

                branch_ok, current_branch = verify_trusted_branch(
                    repo_root, self._run_git)
                if not branch_ok:
                    self._print_error(
                        WRONG_BRANCH_MSG.format(
                            branch=OFFICIAL_BRANCH,
                            current=current_branch,
                        )
                    )
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='wrong_branch',
                        trusted_branch=OFFICIAL_BRANCH,
                        current_branch=current_branch,
                    )
                    return

                clean, status_lines = check_working_tree(
                    repo_root, self._run_git)
                working_tree_status = (
                    'clean' if clean else 'dirty')
                self.audit.log(
                    'UPDATE_WORKING_TREE',
                    status=working_tree_status,
                )
                if not clean:
                    self._print_error(
                        _format_dirty_tree_message(status_lines))
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='dirty_working_tree',
                    )
                    return

                self._print_info(
                    f'Fetching updates from {OFFICIAL_REPO_URL} '
                    f'({OFFICIAL_BRANCH})...'
                )
                fetch = _fetch_official_branch(repo_root)
                if fetch.returncode != 0:
                    self._print_error(
                        _git_error(fetch, 'git fetch failed'))
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='fetch_failure',
                        repository=OFFICIAL_REPO_URL,
                    )
                    return

                local = self._run_git(
                    'rev-parse', 'HEAD', cwd=repo_root)
                if local.returncode != 0:
                    self._print_error(
                        _git_error(
                            local,
                            'Unable to read current revision',
                        )
                    )
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='read_current_revision_failed',
                    )
                    return
                previous_revision = local.stdout.strip()

                target_revision = _get_official_tip(repo_root)
                if target_revision is None:
                    self._print_error(
                        f'Unable to determine the official branch '
                        f'tip from {OFFICIAL_FETCH_REF}.'
                    )
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='target_identification_failed',
                    )
                    return

                self.audit.log(
                    'UPDATE_STARTED',
                    current_revision=previous_revision,
                    target_revision=target_revision,
                    repository=OFFICIAL_REPO_URL,
                    trusted_branch=OFFICIAL_BRANCH,
                )

                if previous_revision == target_revision:
                    self._print_success(UP_TO_DATE_MSG)
                    self.audit.log(
                        'UPDATE_COMPLETED',
                        previous_revision=previous_revision,
                        new_revision=target_revision,
                        final_result='already_current',
                    )
                    clear_state()
                    return

                ff_state, ff_error = _is_fast_forwardable(
                    repo_root, target_revision)
                if ff_state == 'unknown':
                    self._print_error(ff_error)
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='ancestor_check_failed',
                    )
                    return
                diverged = (ff_state == 'no')

                commit_count, commits, shortstat = (
                    _collect_update_preview(
                        repo_root,
                        previous_revision,
                        target_revision,
                    )
                )

                print(
                    f"{colors['yellow']}An update is available for "
                    f"TornadoC2.{colors['end']}"
                )
                print(
                    f"Source:         {OFFICIAL_REPO_URL} "
                    f"({OFFICIAL_BRANCH})"
                )
                print(
                    f"Current commit: "
                    f"{_short_revision(previous_revision)}"
                )
                print(
                    f"Target commit:  "
                    f"{_short_revision(target_revision)}"
                )
                print(f"Commits:        {commit_count}")
                if shortstat:
                    print(f"Changes:        {shortstat}")
                if commits:
                    print('Summary:')
                    for entry in commits:
                        print(f"  {entry}")

                if diverged:
                    print()
                    self._print_warning(DIVERGED_FORK_HEADER)

                print(
                    f"{colors['yellow']}Updating will restart "
                    f"TornadoC2 and terminate all active beacon "
                    f"sessions, SOCKS proxies, tunnels, and other "
                    f"runtime state.{colors['end']}"
                )

                apply_method = 'merge'
                if diverged:
                    try:
                        answer = input(
                            f"{colors['red']}{DIVERGED_FORK_PROMPT}"
                            f"{colors['end']}"
                        ).strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        self._print_warning('Update cancelled.')
                        self.audit.log(
                            'UPDATE_ABORTED',
                            reason='operator_cancelled',
                            operator_confirmed='no',
                        )
                        return
                    if answer.lower() != 'reset':
                        self._print_warning('Update cancelled.')
                        self.audit.log(
                            'UPDATE_ABORTED',
                            reason='operator_declined',
                            operator_confirmed='no',
                        )
                        return
                    apply_method = 'reset'
                else:
                    try:
                        answer = input(
                            f"{colors['cyan']}Proceed with update? "
                            f"[y/N]: {colors['end']}"
                        ).strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        self._print_warning('Update cancelled.')
                        self.audit.log(
                            'UPDATE_ABORTED',
                            reason='operator_cancelled',
                            operator_confirmed='no',
                        )
                        return
                    if answer not in ('y', 'yes'):
                        self._print_warning('Update cancelled.')
                        self.audit.log(
                            'UPDATE_ABORTED',
                            reason='operator_declined',
                            operator_confirmed='no',
                        )
                        return

                operator_confirmed = 'yes'

                begin_update(
                    previous_revision=previous_revision,
                    target_revision=target_revision,
                    repository=OFFICIAL_REPO_URL,
                    branch=OFFICIAL_BRANCH,
                )

                set_state(STATE_APPLYING)
                if apply_method == 'reset':
                    self._print_info(
                        'Resetting to the official revision...')
                    apply_result = self._run_git(
                        'reset', '--hard', target_revision,
                        cwd=repo_root,
                        timeout=GIT_TIMEOUT_APPLY,
                    )
                else:
                    self._print_info('Applying update...')
                    apply_result = self._run_git(
                        'merge', '--ff-only', target_revision,
                        cwd=repo_root,
                        timeout=GIT_TIMEOUT_APPLY,
                    )

                if apply_result.returncode != 0:
                    set_state(
                        STATE_FAILED,
                        failure_reason=_git_error(
                            apply_result, 'apply failed'),
                    )
                    self._print_error(
                        _git_error(
                            apply_result,
                            'Failed to apply update',
                        )
                    )
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='apply_failure',
                        apply_method=apply_method,
                        operator_confirmed=operator_confirmed,
                    )
                    return

                self.audit.log(
                    'UPDATE_APPLIED',
                    target_revision=target_revision,
                    apply_method=apply_method,
                )

                set_state(STATE_VALIDATING)
                ok, detail = validate_installation(repo_root)
                self.audit.log(
                    'UPDATE_VALIDATION',
                    result='success' if ok else 'failure',
                    detail=detail,
                )
                if not ok:
                    set_state(
                        STATE_FAILED,
                        failure_reason=detail,
                        validation_result='failure',
                    )
                    self._print_error(
                        f'Post-update validation failed: {detail}')
                    set_state(STATE_ROLLING_BACK)
                    rolled_back, rollback_detail = (
                        rollback_to_revision(
                            repo_root,
                            previous_revision,
                            self._run_git,
                        )
                    )
                    rollback_result = (
                        'success' if rolled_back else 'failure')
                    self.audit.log(
                        'UPDATE_ROLLBACK',
                        result=rollback_result,
                        detail=rollback_detail,
                        previous_revision=previous_revision,
                    )
                    if rolled_back:
                        rollback_ok, rb_detail = (
                            validate_installation(repo_root))
                        self.audit.log(
                            'UPDATE_ROLLBACK_VALIDATION',
                            result=(
                                'success' if rollback_ok
                                else 'failure'),
                            detail=rb_detail,
                        )
                        set_state(STATE_ROLLED_BACK)
                        if rollback_ok:
                            self._print_warning(
                                'Update validation failed. The '
                                'installation was rolled back to '
                                'the previous known-good revision.'
                            )
                        else:
                            self._print_error(
                                'Update validation failed and '
                                'rollback validation also failed: '
                                f'{rb_detail}'
                            )
                    else:
                        self._print_error(
                            f'Rollback failed: {rollback_detail}')
                    self.audit.log(
                        'UPDATE_COMPLETED',
                        previous_revision=previous_revision,
                        new_revision=previous_revision,
                        final_result='validation_failed',
                    )
                    return

                set_state(
                    STATE_COMPLETED, validation_result='success')
                self._print_success(UPDATE_SUCCESS_MSG)
                self.audit.log(
                    'UPDATE_COMPLETED',
                    previous_revision=previous_revision,
                    new_revision=target_revision,
                    final_result='success',
                    operator_confirmed=operator_confirmed,
                    apply_method=apply_method,
                )
                clear_state()
                sys.stdout.flush()
                try:
                    self.h.shutdown_for_restart()
                    _restart_process()
                except Exception as exc:
                    self._print_error(
                        f'Failed to restart TornadoC2: {exc}')
                    self.audit.log(
                        'UPDATE_ABORTED',
                        reason='restart_failure',
                        detail=str(exc),
                    )

        except UpdateLockError as exc:
            self._print_warning(str(exc))
            self.audit.log(
                'UPDATE_ABORTED',
                reason='lock_acquisition_failure',
            )
        except Exception as exc:
            self._print_error(f'Unexpected update failure: {exc}')
            self.audit.log(
                'UPDATE_ABORTED',
                reason='unexpected_exception',
                detail=str(exc),
            )
            if repo_root and previous_revision and target_revision:
                set_state(STATE_ROLLING_BACK)
                rolled_back, rollback_detail = rollback_to_revision(
                    repo_root, previous_revision, self._run_git)
                self.audit.log(
                    'UPDATE_ROLLBACK',
                    result='success' if rolled_back else 'failure',
                    detail=rollback_detail,
                )
                if rolled_back:
                    set_state(STATE_ROLLED_BACK)
        finally:
            self._busy = False