"""Post-update installation validation."""

import ast
import compileall
import os
import subprocess
import sys

PACKAGE_NAME = 'tornadoc2'
ENTRY_POINT = 'tornadoc2.py'
HANDLER_MODULE = 'beacon_handler'


def _install_root():
    return os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )


def _required_paths(repo_root):
    return (
        os.path.join(repo_root, ENTRY_POINT),
        os.path.join(repo_root, PACKAGE_NAME, f'{HANDLER_MODULE}.py'),
        os.path.join(repo_root, PACKAGE_NAME, 'updater.py'),
    )


def validate_python_syntax(repo_root):
    package_dir = os.path.join(repo_root, PACKAGE_NAME)
    if not os.path.isdir(package_dir):
        return False, f'Missing {PACKAGE_NAME} package directory'

    failures = []
    for root, _, files in os.walk(package_dir):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, 'r', encoding='utf-8') as handle:
                    ast.parse(handle.read(), filename=path)
            except SyntaxError as exc:
                failures.append(f'{path}: {exc.msg}')

    if failures:
        return False, '; '.join(failures[:5])
    return True, ''


def validate_required_files(repo_root):
    missing = [
        path for path in _required_paths(repo_root)
        if not os.path.isfile(path)
    ]
    if missing:
        return False, 'Missing required files: ' + ', '.join(missing)
    return True, ''


def _import_error_detail(result):
    output = (result.stderr or result.stdout or 'unknown error').strip()
    if not output:
        return 'unknown error'
    for line in reversed(output.splitlines()):
        stripped = line.strip()
        if stripped.startswith((
                'ImportError', 'ModuleNotFoundError',
                'SyntaxError', 'Exception')):
            return stripped
    return output.splitlines()[-1].strip()


def validate_handler_import(repo_root):
    """Import the handler in a child process so package-relative
    imports resolve."""
    snippet = (
        'import sys; '
        f'sys.path.insert(0, {repo_root!r}); '
        f'import {PACKAGE_NAME}.{HANDLER_MODULE}'
    )
    try:
        result = subprocess.run(
            [sys.executable, '-c', snippet],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
        )
    except subprocess.TimeoutExpired:
        return False, 'Handler import timed out'
    except OSError as exc:
        return False, f'Handler import failed: {exc}'

    if result.returncode != 0:
        return False, (
            f'Handler import failed: {_import_error_detail(result)}'
        )
    return True, ''


def validate_installation(repo_root=None):
    repo_root = repo_root or _install_root()

    ok, detail = validate_required_files(repo_root)
    if not ok:
        return False, detail

    ok, detail = validate_python_syntax(repo_root)
    if not ok:
        return False, detail

    ok, detail = validate_handler_import(repo_root)
    if not ok:
        return False, detail

    if not compileall.compile_dir(
        os.path.join(repo_root, PACKAGE_NAME),
        quiet=1,
        legacy=False,
    ):
        return False, (
            'Bytecode compilation failed for one or more modules'
        )

    return True, ''