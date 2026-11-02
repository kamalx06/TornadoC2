"""Local-console support for the beacon subsystem.

The interactive per-beacon console — `attach()`, `_dispatch()`, the
full verb catalogue, `exec`/`cat`/`ls`/`upload`/`download`/`bof`/
`execute-assembly`/`extension`/`migrate`/`socks`/`steal_token` and
the rest — lives in the remote operator client
(`tornado_client/repl.py`). It is not reachable from the local
handler, and the local handler does not attach to beacons.

This module now provides the two things the local handler still
needs:

  * `print_list()` — renders the `beacons` / `bl` output.
  * `_list_local_extensions()` — feeds the readline completer.

Both are called from `tornadoc2.beacon_handler._main_loop()` and
`tornadoc2.beacon_handler.BeaconHandler._complete_extension_names()`
respectively. Nothing else in the tree imports this module.

The per-beacon verbs are reached from the remote client with
`use <id>`. See README.md › Operator Reference › Beacon console.
"""

from __future__ import annotations

import json as _json
import os as _os


class BeaconConsole:
    """Local-console support for the beacon subsystem.

    Holds a reference to the engine (for `print_list()`) and to the
    handler (for the color dictionary). It is not a per-beacon
    console; the class name is preserved so existing call sites —
    `BeaconConsole(self.beacon, self)` in `_start()` and
    `self.beacon_console.print_list()` in `_main_loop()` — keep
    working without touching `beacon_handler.py`.
    """

    def __init__(self, engine, handler):
        self.engine = engine
        self.handler = handler
        self.c = handler.colors

    # ------------------------------------------------------------------
    # `beacons` / `bl`

    def print_list(self) -> None:
        """Render the beacon list.

        One line per session. Alive beacons get a green dot, stale
        ones a red dot. `rejected_results` renders inline when the
        engine has counted any (a signature failure on a result
        from this session).
        """
        c = self.c
        sessions = self.engine.list_all()
        alive = [s for s in sessions if s.alive]
        print(f"\n{c['cyan']}BEACONS | Active: {len(alive)}{c['end']}")
        if not sessions:
            print(f"{c['yellow']}No beacons seen{c['end']}")
            return
        for s in sessions:
            dot = (f"{c['green']}●{c['end']}" if s.alive
                   else f"{c['red']}○{c['end']}")
            ident = s.identity
            os_name = ident.get('os', '?')
            arch = ident.get('arch', '')
            rejected = getattr(s, 'rejected_results', 0)
            extra = ""
            if rejected:
                extra = f" {c['red']}rejected={rejected}{c['end']}"
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
    # Extension discovery — feeds the readline completer

    def _extension_dir(self) -> str:
        """Directory that holds one subdirectory per extension."""
        here = _os.path.dirname(_os.path.abspath(__file__))
        pkg_root = _os.path.dirname(here)
        return _os.path.join(pkg_root, 'extensions')

    def _load_extension_manifest(self, path):
        """Parse `extension.json` from a directory or a direct path.

        Returns the manifest dict (with `_dir` set to the directory
        that holds the manifest) or None if the file is missing,
        unparseable, or lacks a `name` field.
        """
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

    def _list_local_extensions(self) -> dict:
        """Return `{name: manifest}` for every extension in the
        operator-side store.

        The readline completer uses the keys to suggest extension
        names after `extension load`, `extension info`, and so on.
        """
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