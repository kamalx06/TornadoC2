#!/usr/bin/env python3
"""Entry point — dispatches to CLI or GUI based on --gui.

The CLI (tornado_client.repl) is unchanged and remains the default.
``--gui`` starts the Electron shell (this tree). ``--gui-classic`` is
accepted as a no-op alias now that the Qt console is gone. Both
frontends connect through the same Python client.
"""

import os
import subprocess
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DESKTOP = os.path.join(_REPO, 'client', 'desktop')


def _run_cli() -> int:
    from tornado_client.repl import main
    return main()


def _config_arg(argv) -> str:
    for i, a in enumerate(argv):
        if a in ('-c', '--config') and i + 1 < len(argv):
            return argv[i + 1]
    return ''


def _electron_command(argv):
    """Return (argv, cwd) for the Electron shell, or None."""
    cfg = _config_arg(argv)
    override = os.environ.get('TORNADOC2_GUI_BIN')
    if override:
        return ([override, '--config', cfg] if cfg else [override]), _REPO

    launcher = '/usr/local/bin/tornadoc2-desktop'
    if os.access(launcher, os.X_OK):
        return ([launcher, '--config', cfg] if cfg else [launcher]), _REPO
    for rel in ('dist/linux-unpacked/tornadoc2-desktop',
                'dist/linux-unpacked/TornadoC2',
                'dist/win-unpacked/TornadoC2.exe'):
        exe = os.path.join(_DESKTOP, rel)
        if os.path.isfile(exe):
            return ([exe, '--config', cfg] if cfg else [exe]), _DESKTOP

    electron = os.path.join(_DESKTOP, 'node_modules', '.bin', 'electron')
    if os.path.isfile(electron) and os.path.isdir(
            os.path.join(_DESKTOP, 'out')):
        cmd = [electron, _DESKTOP]
        if cfg:
            cmd += ['--config', cfg]
        return cmd, _DESKTOP
    return None


def _run_gui(argv) -> int:
    found = _electron_command(argv)
    if found is None:
        print('Electron shell not built.\n'
              '  cd client/desktop && npm ci && npm run build',
              file=sys.stderr)
        return 2
    cmd, cwd = found
    env = dict(os.environ)
    env.setdefault('TORNADOC2_REPO', _REPO)
    try:
        return subprocess.call(cmd, cwd=cwd, env=env)
    except FileNotFoundError as exc:
        print(f'cannot start Electron ({exc})', file=sys.stderr)
        return 2


def _run_ai(argv) -> int:
    from tornadoc2_mcp.console import main_ai
    return main_ai(argv)


def main() -> int:
    argv = sys.argv[1:]

    if argv and argv[0] == 'ai':
        return _run_ai(argv[1:])

    gui = '--gui' in argv or '--gui-classic' in argv
    sys.argv = [sys.argv[0]] + [
        a for a in argv if a not in ('--gui', '--gui-classic')]
    return _run_gui(argv) if gui else _run_cli()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
    except Exception as exc:
        if '--debug' in sys.argv:
            raise
        print(f"unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)