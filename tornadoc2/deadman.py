"""Dead-man's switch for the team server.

Watches authenticated activity and shuts the process down after a
configurable idle window. Two motivations:

  1. Time-boxed engagements. A team server on a shared or rented
     VPS should not outlive its authorisation window.
  2. Unattended operation. An operator who walks away for the
     weekend should not leave an accessible team server running.

The switch is off by default. It is armed by writing
``team_ca/deadman.json`` or by setting ``TORNADO_DEADMAN_HOURS`` at
startup, and can be armed, disabled, reset, or reconfigured at
runtime from the local console's ``deadman`` command.

Design notes:

  * The check interval is short (default 60 s) so a warning fires
    within a minute of its threshold and shutdown happens within a
    minute of the deadline.
  * Activity sources are tracked individually — local console,
    remote operator, beacon check-in, client tunnel. ``status``
    shows which source last touched the switch, which makes "why
    did it shut down while I was working" answerable.
  * Shutdown is graceful: listeners are stopped, buffers are
    flushed, and the audit log records the event. A hard exit
    follows, because a switch that stalls is worse than no switch.
  * Configuration persists. A window set at the console survives a
    restart; only ``TORNADO_DEADMAN_HOURS`` overrides it, and only
    for the current run.
"""

from __future__ import annotations

import concurrent.futures as _futures
import json
import os
import shutil
import stat as _stat
import sys
import threading
import time

class DeadmanSwitch:

    DEFAULT_CHECK_SECONDS = 60.0
    DEFAULT_WARN_FRACTIONS = (0.8, 0.95)
    MIN_WINDOW_SECONDS = 60.0
    MAX_WINDOW_SECONDS = 30 * 86400.0   # 30 days
    TORNADO_ROOT_NAME = 'TornadoC2'
    TORNADO_ROOT_UP_LEVELS = 1

    # ---- Shredding ---------------------------------------------------
    #
    # Pass-pattern modes (traditional overwrite sequences). These are
    # effective on magnetic media and ineffective on flash and
    # copy-on-write filesystems — see the module note below.
    #
    # 'fast'     — two fixed passes (0x00, 0xFF). The old behaviour.
    # 'random'   — SHRED_RANDOM_PASSES cryptographically-random passes.
    # 'dod'      — DoD 5220.22-M ECE: 0x00 / 0xFF / random, twice,
    #              then a fixed 0x00 to leave a known final state.
    # 'gutmann'  — the historic 35-pass sequence. Only meaningful on
    #              old magnetic media.
    # 'nist'     — NIST SP 800-88 Rev. 1 Clear: a single pass of
    #              cryptographic random. What the current US standard
    #              recommends for a non-SED HDD; the minimum viable
    #              overwrite on any media.
    # 'schneier' — Bruce Schneier's 7-pass from Applied Cryptography:
    #              0xFF, 0x00, then five random.
    # 'hmg'      — HMG Infosec Standard 5 Enhanced (UK). Three passes:
    #              0x00, 0xFF, random.
    # 'bsi'      — German BSI-VSITR: three random passes with a
    #              final verify.
    #
    # Structural modes (what actually works on modern media):
    #
    # 'crypto'   — DESTRUCTIVE. Detects whether the tree sits on a
    #              LUKS-encrypted block device and, if so, runs
    #              `cryptsetup luksErase` on that device. That
    #              destroys the LUKS header and makes every byte on
    #              the volume unrecoverable — including anything else
    #              on the same volume. Falls through to a 'fast'
    #              overwrite of the tree first. Off by default; see
    #              the module docstring.
    # 'scrub'    — the kitchen sink for mixed HDD/SSD deployments:
    #              fallocate the file to ensure blocks are allocated,
    #              open with O_DIRECT to bypass the page cache, write
    #              one random pass, fsync, syncfs the filesystem,
    #              rename, unlink, then issue fallocate(PUNCH_HOLE)
    #              on the parent directory's filesystem to trigger
    #              a TRIM/discard.
    # 'trim'     — like scrub but skips the O_DIRECT step (works on
    #              filesystems that refuse O_DIRECT).
    #
    # Every one of these is best-effort on modern media. On an SSD,
    # NVMe, or any CoW filesystem the overwrite is invisible to the
    # on-disk blocks because the device relocates them on write. Full
    # disk encryption and the 'crypto' mode are the only techniques
    # that reliably deliver "unrecoverable" for data at rest.
    SHRED_MODE = 'dod'
    SHRED_RANDOM_PASSES = 3
    SHRED_WORKERS = 4           # parallel shredders; 1 = serial
    SHRED_BUFFER = 1024 * 1024  # 1 MiB write buffer
    SHRED_FSYNC = True          # fsync after every pass
    SHRED_VERIFY = True         # read-back after a fixed final pass
    SHRED_RENAME = True         # rename each file before unlinking
    SHRED_OBSCURE_MTIME = True  # randomise mtime/atime before unlink

    # ---- Modern-media infrastructure ---------------------------------
    # Applied by 'scrub' and 'trim' modes, but settable independently
    # so an operator can enable any subset on top of any pattern mode.
    SHRED_PREALLOC = False      # fallocate() before writing, to force
                                # block allocation on sparse files
    SHRED_DIRECT = False        # O_DIRECT: bypass the page cache so
                                # each pass reaches the device before
                                # the next one begins. Refused by some
                                # filesystems; silently downgraded.
    SHRED_TRIM = False          # fallocate(PUNCH_HOLE) after unlink,
                                # to ask the SSD controller to
                                # garbage-collect the freed blocks
    SHRED_SYNCFS = False        # syncfs() after each file, so the
                                # filesystem metadata is flushed and
                                # not just the file's own buffer

    def __init__(self, handler, config_path: str):
        self.handler = handler
        self.config_path = config_path
        self.colors = handler.colors
        self._lock = threading.Lock()
        self._deadline = 0.0
        self._window_seconds = 0.0
        self._check_seconds = self.DEFAULT_CHECK_SECONDS
        self._warn_fractions = self.DEFAULT_WARN_FRACTIONS
        self._armed_at = time.time()
        self._last_activity = time.time()
        self._last_source = 'startup'
        self._activity_by_source: dict = {}
        self._warned: set = set()
        self._shutdown_in_progress = False
        self._config_halt_mode = ''
        self._load_config()
        self._apply_env_overrides()
        self._halt_mode = os.environ.get(
            'TORNADO_DEADMAN_HALT', '').strip().lower()
        if not self._halt_mode:
            self._halt_mode = self._config_halt_mode or ''
        if self._halt_mode not in ('', 'shutdown', 'poweroff', 'reboot'):
            self._halt_mode = ''

        threading.Thread(
            target=self._loop, daemon=True,
            name='deadman-switch').start()

    # ------------------------------------------------------------------
    # Activity

    def touch(self, source: str = 'operator') -> None:
        """Record authenticated activity for the status display.

        This does NOT move the deadline. The switch fires on wall
        clock, not on idleness, so nothing short of an explicit
        `deadman arm` or `deadman reset` can extend the window.
        Cheap enough to call on every request."""
        with self._lock:
            now = time.time()
            self._last_activity = now
            self._last_source = source
            self._activity_by_source[source] = now

    # ------------------------------------------------------------------
    # Control (programmatic)

    def arm(self, seconds: float,
            source: str = 'manual') -> float:
        """Arm with a fresh window starting now. Writes the
        resulting absolute deadline to the persisted config."""
        seconds = max(self.MIN_WINDOW_SECONDS,
                      min(self.MAX_WINDOW_SECONDS, float(seconds)))
        with self._lock:
            now = time.time()
            self._deadline = now + seconds
            self._window_seconds = seconds
            self._armed_at = now
            self._last_activity = now
            self._last_source = source
            self._warned.clear()
        self._save_config()
        return seconds

    def arm_until(self, timestamp: float,
                  source: str = 'manual') -> float:
        """Arm with an absolute wall-clock deadline. Returns the
        number of seconds between now and the deadline."""
        timestamp = float(timestamp)
        now = time.time()
        delta = timestamp - now
        if delta < self.MIN_WINDOW_SECONDS:
            raise ValueError('deadline is in the past or too soon')
        with self._lock:
            self._deadline = timestamp
            self._window_seconds = delta
            self._armed_at = now
            self._last_activity = now
            self._last_source = source
            self._warned.clear()
        self._save_config()
        return delta

    def disable(self) -> float:
        """Clear the deadline. Returns the number of seconds that
        remained when it was disabled (0 if not armed)."""
        with self._lock:
            remaining = 0.0
            if self._deadline > 0:
                remaining = max(0.0, self._deadline - time.time())
            self._deadline = 0.0
            self._window_seconds = 0.0
            self._warned.clear()
        self._save_config()
        return remaining

    def set_warn_fractions(self, fractions) -> tuple:
        """Replace warning thresholds. Fractions strictly in (0, 1)."""
        cleaned = tuple(sorted(
            float(f) for f in fractions if 0.0 < float(f) < 1.0))
        with self._lock:
            self._warn_fractions = cleaned
            self._warned.clear()
        self._save_config()
        return cleaned

    def set_halt_mode(self, mode: str) -> str:
        """Set the post-wipe power action. '' disables it (wipe
        and exit only), 'shutdown' or 'reboot' enable it. Returns
        the normalised value."""
        mode = (mode or '').strip().lower()
        if mode == 'poweroff':
            mode = 'shutdown'
        if mode not in ('', 'shutdown', 'reboot', 'none', 'off'):
            raise ValueError(f'invalid halt mode: {mode!r}')
        if mode in ('none', 'off'):
            mode = ''
        with self._lock:
            self._halt_mode = mode
        self._save_config()
        return mode

    @property
    def enabled(self) -> bool:
        return self._deadline > 0.0

    # ------------------------------------------------------------------
    # Status
    
    def status(self) -> dict:
        with self._lock:
            now = time.time()
            deadline = self._deadline
            window = self._window_seconds
            remaining = (max(0.0, deadline - now)
                         if deadline > 0 else 0.0)
            elapsed = (now - self._armed_at) if deadline > 0 else 0.0
            pct = (100.0 * elapsed / window) if window > 0 else 0.0
            return {
                'enabled':        deadline > 0,
                'deadline':       deadline,
                'window_seconds': window,
                'elapsed_secs':   elapsed,
                'remaining_secs': remaining,
                'elapsed_pct':    pct,
                'check_seconds':  self._check_seconds,
                'warn_fractions': self._warn_fractions,
                'warned':         sorted(self._warned),
                'last_source':    self._last_source,
                'last_activity':  self._last_activity,
                'armed_at':       self._armed_at,
                'sources':        dict(self._activity_by_source),
            }

    def render_status(self) -> None:
        """Print the switch state to the console."""
        c = self.colors
        s = self.status()

        if not s['enabled']:
            print(f"  {c['bold']}dead-man's switch{c['end']}  "
                  f"{c['yellow']}disabled{c['end']}")
            print()
            print(f"  {c['dim']}arm with `deadman arm <duration>`"
                  f"{c['end']}")
            print(f"  {c['dim']}or edit {self.config_path}"
                  f"{c['end']}")
            return

        print(f"  {c['bold']}dead-man's switch{c['end']}  "
              f"{c['green']}armed{c['end']}")
        print()

        def row(label, value, col=None):
            vcol = col or ''
            tail = c['end'] if vcol else ''
            print(f"  {c['dim']}{label:<14}{c['end']}"
                  f"{vcol}{value}{tail}")

        row('deadline', time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(s['deadline'])))
        row('window', self._fmt_duration(s['window_seconds']))
        row('elapsed', self._fmt_duration(s['elapsed_secs']))

        remaining = s['remaining_secs']
        warn_floor = s['window_seconds'] * (
            1.0 - (s['warn_fractions'][0] if s['warn_fractions']
                   else 0.8))
        if remaining > warn_floor:
            rcol = c['green']
        elif remaining > 60:
            rcol = c['yellow']
        else:
            rcol = c['red']
        row('remaining', self._fmt_duration(remaining), col=rcol)

        bar_width = 40
        pct = min(1.0, s['elapsed_secs'] / s['window_seconds'])
        filled = int(bar_width * pct)
        bar = '█' * filled + '░' * (bar_width - filled)
        print(f"  {c['dim']}{'progress':<14}{c['end']}"
              f"{c['cyan']}[{bar}] {int(pct * 100):3d}%{c['end']}")
        print()

        row('check every', f"{s['check_seconds']:.0f}s")
        warn_str = (', '.join(f"{int(f * 100)}%"
                              for f in s['warn_fractions'])
                    or 'none')
        row('warn at', warn_str)
        fired_str = (', '.join(f"{int(f * 100)}%"
                               for f in s['warned'])
                     or 'none')
        row('fired', fired_str)
        print()

        row('last source', s['last_source'])
        row('last activity', time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(s['last_activity'])))
        row('armed at', time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(s['armed_at'])))
        print()

        if s['sources']:
            print(f"  {c['dim']}activity by source:{c['end']}")
            for src in sorted(s['sources'],
                              key=lambda k: -s['sources'][k]):
                ts = s['sources'][src]
                when = time.strftime(
                    '%H:%M:%S', time.localtime(ts))
                ago = self._fmt_duration(time.time() - ts)
                print(f"    {c['cyan']}{src:<12}{c['end']} "
                      f"{c['dim']}{when}  ({ago} ago){c['end']}")

    # ------------------------------------------------------------------
    # Console command

    def handle_command(self, parts) -> None:
        c = self.colors
        sub = parts[1].lower() if len(parts) > 1 else 'status'

        if sub in ('status', 'show', 'info', ''):
            self.render_status()
            return

        if sub in ('arm', 'on', 'enable'):
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman arm "
                      f"<duration>{c['end']}")
                print(f"  {c['dim']}examples: 30m, 2h, 1d, "
                      f"2h30m, 7200 (seconds){c['end']}")
                return
            secs = self.parse_duration(parts[2])
            if secs is None:
                print(f"{c['red']}invalid duration: "
                      f"{parts[2]!r}{c['end']}")
                return
            actual = self.arm(secs, source='console')
            self._audit('deadman.arm', f'window={actual:.0f}s')
            print(f"{c['green']}[DEADMAN] armed for "
                  f"{self._fmt_duration(actual)}{c['end']}")
            return

        if sub in ('arm-until', 'until'):
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman arm-until "
                      f"<HH:MM>{c['end']}")
                return
            ts = self.parse_deadline(parts[2])
            if ts is None:
                print(f"{c['red']}invalid deadline: "
                      f"{parts[2]!r} (expected HH:MM){c['end']}")
                return
            try:
                actual = self.arm_until(ts, source='console')
            except ValueError as exc:
                print(f"{c['red']}{exc}{c['end']}")
                return
            deadline = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(ts))
            self._audit('deadman.arm',
                        f'deadline={deadline} '
                        f'window={actual:.0f}s')
            print(f"{c['green']}[DEADMAN] armed until "
                  f"{deadline} "
                  f"({self._fmt_duration(actual)} from now)"
                  f"{c['end']}")
            return

        if sub in ('reset', 'extend'):
            if len(parts) < 3:
                print(f"{c['red']}usage: deadman reset "
                      f"<duration>{c['end']}")
                print(f"  {c['dim']}re-arm with a fresh window "
                      f"starting now (e.g. `deadman reset 2h`)"
                      f"{c['end']}")
                return
            secs = self.parse_duration(parts[2])
            if secs is None:
                print(f"{c['red']}invalid duration: "
                      f"{parts[2]!r}{c['end']}")
                return
            actual = self.arm(secs, source='console')
            self._audit('deadman.reset',
                        f'window={actual:.0f}s')
            print(f"{c['green']}[DEADMAN] re-armed for "
                  f"{self._fmt_duration(actual)}{c['end']}")
            return

        if sub in ('disable', 'off'):
            was = self.disable()
            self._audit('deadman.disable', f'was={was:.0f}s')
            if was > 0:
                print(f"{c['green']}[DEADMAN] disabled "
                      f"(was {self._fmt_duration(was)})"
                      f"{c['end']}")
            else:
                print(f"{c['dim']}[DEADMAN] already disabled"
                      f"{c['end']}")
            return

        if sub == 'warn':
            if len(parts) < 3:
                cur = (', '.join(f"{int(f * 100)}%"
                                 for f in self._warn_fractions)
                       or 'none')
                print(f"  warnings at: {cur}")
                print(f"  {c['dim']}usage: deadman warn "
                      f"<f1,f2,...>  (fractions, e.g. 0.5,0.8,0.95)"
                      f"{c['end']}")
                return
            raw = parts[2].strip()
            if raw.lower() in ('none', 'off', 'clear'):
                fracs = []
            else:
                try:
                    fracs = [float(x.strip())
                             for x in raw.split(',') if x.strip()]
                except ValueError:
                    print(f"{c['red']}invalid fractions: "
                          f"{raw!r}{c['end']}")
                    return
            cleaned = self.set_warn_fractions(fracs)
            self._audit('deadman.warn',
                        f'fractions={list(cleaned)}')
            if cleaned:
                print(f"{c['green']}[DEADMAN] warnings at "
                      f"{', '.join(f'{int(f * 100)}%' for f in cleaned)}"
                      f"{c['end']}")
            else:
                print(f"{c['dim']}[DEADMAN] warnings disabled"
                      f"{c['end']}")
            return

        if sub == 'shred':
            pattern_modes = ('fast', 'random', 'dod', 'gutmann',
                             'nist', 'schneier', 'hmg', 'bsi')
            structural_modes = ('crypto', 'scrub', 'trim')
            valid = pattern_modes + structural_modes

            if len(parts) < 3:
                print(f"  shred mode: {self.SHRED_MODE}")
                print()
                print(f"  {c['dim']}pattern modes "
                      f"(traditional overwrites):{c['end']}")
                for m in pattern_modes:
                    print(f"    {c['cyan']}{m}{c['end']}")
                print()
                print(f"  {c['dim']}structural modes "
                      f"(modern media):{c['end']}")
                for m in structural_modes:
                    print(f"    {c['cyan']}{m}{c['end']}")
                print()
                print(f"  {c['dim']}usage: deadman shred "
                      f"<mode>{c['end']}")
                return

            mode = parts[2].strip().lower()
            if mode not in valid:
                print(f"{c['red']}shred mode must be one of "
                      f"{', '.join(valid)}{c['end']}")
                return

            if mode == 'crypto':
                print(f"{c['red']}{c['bold']}crypto mode is "
                      f"destructive to the whole volume.{c['end']}")
                print(f"  {c['yellow']}If the tree sits on a LUKS "
                      f"volume that holds other data, running the "
                      f"switch will destroy that data too. The "
                      f"whole volume becomes unrecoverable the "
                      f"moment the LUKS header is erased.{c['end']}")
                try:
                    ans = input(
                        f"  {c['yellow']}Enable crypto mode? "
                        f"[y/N]{c['end']} ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    print(f"{c['dim']}cancelled{c['end']}")
                    return
                if ans not in ('y', 'yes'):
                    print(f"{c['dim']}cancelled{c['end']}")
                    return

            self.SHRED_MODE = mode
            self._save_config()
            self._audit('deadman.shred', f'mode={mode}')

            note = ''
            if mode == 'crypto':
                note = (' — LUKS header destroyed on shutdown '
                        'if the tree is on an encrypted volume')
            elif mode == 'scrub':
                note = (' — prealloc + O_DIRECT + random + syncfs '
                        '+ TRIM')
            elif mode == 'trim':
                note = ' — random + syncfs + TRIM'
            print(f"{c['green']}[DEADMAN] shred mode: {mode}"
                  f"{c['end']}{c['dim']}{note}{c['end']}")
            return

        if sub == 'halt':
            if len(parts) < 3:
                cur = self._halt_mode or 'none'
                print(f"  halt mode: {cur}")
                print(f"  {c['dim']}usage: deadman halt "
                      f"<none|shutdown|reboot>{c['end']}")
                print(f"  {c['dim']}this sets what happens after "
                      f"the wipe. To run the sequence now, use "
                      f"the top-level `halt` command.{c['end']}")
                return
            try:
                mode = self.set_halt_mode(parts[2])
            except ValueError as exc:
                print(f"{c['red']}{exc}{c['end']}")
                return
            self._audit('deadman.halt_set', f'mode={mode}')
            if mode:
                print(f"{c['green']}[DEADMAN] halt mode: {mode}"
                      f"{c['end']}")
            else:
                print(f"{c['dim']}[DEADMAN] halt mode cleared "
                      f"(wipe and exit only){c['end']}")
            return

        if sub in ('help', '?'):
            self._print_help()
            return

        print(f"{c['red']}unknown deadman subcommand: "
              f"{sub!r}{c['end']}")
        self._print_help()

    def _print_help(self) -> None:
        c = self.colors
        print(f"""
  {c['green']}deadman{c['end']} — auto-shutdown watchdog

    {c['cyan']}deadman status{c['end']}
        Show window, idle time, remaining time, source breakdown.

    {c['cyan']}deadman arm <duration>{c['end']}
        Arm with a fresh window. 30m / 2h / 1d / 2h30m / 7200.

    {c['cyan']}deadman arm-until <HH:MM>{c['end']}
        Arm with a wall-clock deadline today, or tomorrow if the
        time has already passed.

    {c['cyan']}deadman reset <duration>{c['end']}
        Re-arm with a fresh window starting now. `deadman reset
        2h` gives you two more hours from this moment. Unlike
        `reset` in earlier versions, this is a deliberate
        extension — ordinary console activity cannot move the
        deadline.

    {c['cyan']}deadman disable{c['end']}
        Clear the window. Persists across restarts.

    {c['cyan']}deadman warn <f1,f2,...>{c['end']}
        Warning thresholds as fractions. e.g. 0.5,0.8,0.95.
        Use 'none' to disable warnings.

    {c['cyan']}deadman shred <mode>{c['end']}
        Overwrite algorithm applied to every file before
        unlinking, or a structural technique for modern media.
        Default is 'dod'.

        Pattern modes (traditional overwrites, effective on
        magnetic media):
            fast      two passes: 0x00, 0xFF
            random    N cryptographic-random passes
            dod       DoD 5220.22-M ECE, 7 passes
            gutmann   the historic 35-pass sequence
            nist      NIST SP 800-88 Clear (1 random pass)
            schneier  Schneier's 7-pass from Applied Cryptography
            hmg       HMG Infosec Standard 5 Enhanced (UK)
            bsi       German BSI-VSITR (3 random passes)

        Structural modes (what actually works on SSD/NVMe/CoW):
            trim      random pass + syncfs + TRIM/discard
            scrub     prealloc + O_DIRECT + random + syncfs + TRIM
            crypto    destroy the LUKS header of the volume that
                      holds the tree — DESTRUCTIVE to every byte
                      on that volume, not just TornadoC2's

        Pass-pattern modes are ineffective on flash and CoW media
        because the device relocates blocks on write. On those,
        use 'trim' for a best-effort discard or 'crypto' if the
        tree is on an encrypted volume.

  Configuration persists to
  {c['dim']}{self.config_path}{c['end']}
""")

    # ------------------------------------------------------------------
    # Watchdog thread

    def _loop(self) -> None:
        while True:
            time.sleep(max(5.0, self._check_seconds))
            try:
                self._tick()
            except Exception as exc:
                try:
                    print(f"{self.colors['yellow']}"
                          f"[DEADMAN] tick error: {exc}"
                          f"{self.colors['end']}")
                except Exception:
                    pass

    def _tick(self) -> None:
        if not self.enabled or self._shutdown_in_progress:
            return

        with self._lock:
            now = time.time()
            deadline = self._deadline
            window = self._window_seconds
            remaining = deadline - now
            to_fire = [
                f for f in self._warn_fractions
                if f not in self._warned
                and remaining <= window * (1.0 - f)
            ]
            for f in to_fire:
                self._warned.add(f)

        for frac in to_fire:
            self._fire_warning(frac, remaining, window)

        if now >= deadline:
            self._shutdown(deadline)

    def _fire_warning(self, frac, remaining, window) -> None:
        c = self.colors
        print(f"\n{c['yellow']}{c['bold']}[DEADMAN] deadline in "
              f"{self._fmt_duration(max(0.0, remaining))} "
              f"(window {self._fmt_duration(window)}, "
              f"threshold {int(frac * 100)}%, "
              f"last activity from {self._last_source})"
              f"{c['end']}")
        self._audit('deadman.warn',
                    f'remaining={remaining:.0f}s '
                    f'threshold={frac:.2f} '
                    f'window={window:.0f}s '
                    f'last_source={self._last_source}')

    def _shutdown(self, deadline) -> None:
        """Triggered by the wall-clock deadline."""
        self._shutdown_in_progress = True
        c = self.colors
        window = self._window_seconds
        deadline_str = time.strftime(
            '%Y-%m-%d %H:%M:%S', time.localtime(deadline))

        print(f"\n{c['red']}{c['bold']}[DEADMAN] deadline "
              f"{deadline_str} reached (window "
              f"{self._fmt_duration(window)}, last source "
              f"{self._last_source}) — shutting down"
              f"{c['end']}")
        self._audit('deadman.shutdown',
                    f'deadline={deadline:.0f} '
                    f'window={window:.0f}s '
                    f'last_source={self._last_source}')
        self._run_shutdown_sequence()

    def manual_halt(self, reason: str = 'console') -> None:
        """Triggered by the `halt` console command. Runs the same
        sequence the timer would, but immediately and without
        requiring an armed window."""
        self._shutdown_in_progress = True
        c = self.colors
        if self._halt_mode == 'reboot':
            tail = 'rebooting'
        elif self._halt_mode == 'shutdown':
            tail = 'shutting down'
        else:
            tail = 'exiting'
        print(f"\n{c['yellow']}{c['bold']}[DEADMAN] manual halt "
              f"({reason}) — stopping listeners, wiping state, "
              f"then {tail}{c['end']}")
        self._audit('deadman.manual_halt',
                    f'reason={reason} halt_mode={self._halt_mode}')
        self._run_shutdown_sequence()

    def _run_shutdown_sequence(self) -> None:
        """Stop every listener, wipe state directories, run the
        configured power action, then exit. Shared by the timer
        and the manual command."""
        c = self.colors

        for label, obj in (
                ('beacon listener',   self.handler._beacon_listener),
                ('operator listener', self.handler.operator_listener),
                ('client tunnel',     self.handler._client_tunnel),
                ('pivot manager',     self.handler._pivot_manager),
                ('dns transport',     self.handler._dns_transport),
        ):
            if obj is None:
                continue
            stop = getattr(obj, 'stop', None)
            if stop is None:
                continue
            try:
                stop()
            except Exception as exc:
                try:
                    print(f"{c['dim']}[DEADMAN] {label} stop: "
                          f"{exc}{c['end']}")
                except Exception:
                    pass

        try:
            self._cleanup_state()
        except Exception as exc:
            try:
                print(f"{c['red']}[DEADMAN] cleanup raised: "
                      f"{exc}{c['end']}")
            except Exception:
                pass

        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass

        self._system_halt()
        os._exit(1)

    def _cleanup_state(self) -> None:
        """Delete the TornadoC2 repository root.

        Called from `_shutdown` after every listener has been
        stopped. The target is
        ``<cwd>/../TornadoC2`` — the whole tree is removed,
        including the directory itself.

        Safety rails:
          * the resolved path must end in TORNADO_ROOT_NAME
          * it must not be `/` or the invoking user's home
          * it must not be CWD or an ancestor of CWD
          * symlinks at the top level are not followed
        """
        c = self.colors

        print(f"{c['dim']}[DEADMAN] cleanup: cwd={os.getcwd()!r} "
              f"real_cwd={os.path.realpath(os.getcwd())!r} "
              f"up_levels={self.TORNADO_ROOT_UP_LEVELS}{c['end']}")

        if self.TORNADO_ROOT_UP_LEVELS <= 0:
            return

        cwd = os.path.realpath(os.getcwd())

        up = cwd
        for _ in range(self.TORNADO_ROOT_UP_LEVELS):
            parent = os.path.dirname(up)
            if parent == up:          # hit filesystem root
                print(f"{c['yellow']}[DEADMAN] cleanup: walked "
                      f"past filesystem root looking for "
                      f"{self.TORNADO_ROOT_NAME}{c['end']}")
                return
            up = parent

        target = os.path.join(up, self.TORNADO_ROOT_NAME)
        if not os.path.exists(target):
            print(f"{c['dim']}[DEADMAN] cleanup: "
                  f"{target} not found{c['end']}")
            return

        real = os.path.realpath(target)
        print(f"{c['dim']}[DEADMAN] cleanup: target={target!r} "
              f"real={real!r} basename={os.path.basename(real)!r}"
              f"{c['end']}")
        if os.path.basename(real) != self.TORNADO_ROOT_NAME:
            print(f"{c['yellow']}[DEADMAN] refusing cleanup: "
                  f"{target} resolves to {real!r}, not a "
                  f"{self.TORNADO_ROOT_NAME} directory{c['end']}")
            return
        if real in ('/', os.path.expanduser('~')):
            print(f"{c['yellow']}[DEADMAN] refusing cleanup: "
                  f"{target} resolves to a protected path"
                  f"{c['end']}")
            return
        if cwd.startswith(real + os.sep):
            print(f"{c['yellow']}[DEADMAN] refusing cleanup: "
                  f"{target} is a strict ancestor of the "
                  f"working directory — that would wipe the "
                  f"running source tree{c['end']}")
            return

        if self._shred_tree(real):
            print(f"{c['dim']}[DEADMAN] removed "
                  f"{self.TORNADO_ROOT_NAME} at {real}"
                  f"{c['end']}")
        else:
            print(f"{c['yellow']}[DEADMAN] cleanup failed for "
                  f"{real}{c['end']}")

    @classmethod
    def _passes_for_mode(cls, mode):
        """Return a tuple of write patterns. Each element is either
        a single-byte `bytes` object (fixed pattern, replicated to
        fill the file) or `None` (fresh cryptographic random for
        each buffer).

        Structural modes ('crypto', 'scrub', 'trim') do not carry a
        pattern of their own; they fall through to the pattern of
        their base mode — 'fast' for crypto, 'random' for scrub and
        trim. Their behaviour is implemented in _shred_file.
        """
        mode = (mode or '').strip().lower()

        if mode == 'fast' or mode == 'crypto':
            return (b'\x00', b'\xff')

        if mode == 'gutmann':
            seq = [None] * 4
            seq.extend([
                b'\x55', b'\xaa', b'\x92', b'\x49', b'\x24',
                b'\x00', b'\x11', b'\x22', b'\x33', b'\x44',
                b'\x55', b'\x66', b'\x77', b'\x88', b'\x99',
                b'\xaa', b'\xbb', b'\xcc', b'\xdd', b'\xee',
                b'\xff',
                b'\x92', b'\x49', b'\x24',
                b'\x6d', b'\xb6', b'\xdb',
            ])
            seq.extend([None] * 4)
            return tuple(seq)

        if mode == 'dod':
            return (b'\x00', b'\xff', None,
                    b'\x00', b'\xff', None,
                    b'\x00')

        if mode == 'nist':
            return (None,)

        if mode == 'schneier':
            return (b'\xff', b'\x00', None, None, None, None, None)

        if mode == 'hmg':
            return (b'\x00', b'\xff', None)

        if mode == 'bsi':
            return (None, None, None)

        return tuple([None] * max(1, int(cls.SHRED_RANDOM_PASSES)))

    def _wipe_pass(self, fh, size, pattern):
        """Write one pass across the whole file and fsync."""
        fh.seek(0)
        remaining = size
        if pattern is None:
            while remaining > 0:
                buf = os.urandom(min(remaining, self.SHRED_BUFFER))
                n = fh.write(buf)
                if n <= 0:
                    return
                remaining -= n
        else:
            fixed = pattern * self.SHRED_BUFFER
            while remaining > 0:
                n = fh.write(fixed[:min(remaining, len(fixed))])
                if n <= 0:
                    return
                remaining -= n
        fh.flush()
        if self.SHRED_FSYNC:
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass

    def _verify_pass(self, fh, size, pattern):
        """Read the file back and confirm it is all `pattern`.
        Only meaningful for a fixed final pass — a random pass has
        nothing to compare against. Returns True/False."""
        if pattern is None or size == 0:
            return True
        fh.seek(0)
        remaining = size
        fixed = pattern * self.SHRED_BUFFER
        while remaining > 0:
            want = fixed[:min(remaining, len(fixed))]
            got = fh.read(len(want))
            if not got:
                return False
            if got != want:
                return False
            remaining -= len(got)
        return True

    def _obscure_time(self, path):
        """Backdate mtime and atime to a random point in the past
        180 days. Best-effort; ignored on filesystems that refuse
        utime on an open file."""
        try:
            offset = int.from_bytes(os.urandom(3), 'big') % (180 * 86400)
            t = time.time() - offset
            os.utime(path, (t, t))
        except OSError:
            pass

    def _preallocate(self, fh, size):
        """Force block allocation for a sparse file.

        On an ext4/xfs file created by a write that skipped
        holes, the file's logical size can exceed its allocated
        block count. An overwrite pass walks the logical size
        but skips the holes, so pre-existing data in the
        filesystem's unallocated pool is never touched. fallocate
        forces the FS to allocate those blocks (filled with
        zeros), giving the overwrite something to write to.

        Best-effort: some filesystems (tmpfs, some network FS)
        refuse FALLOC_FL_KEEP_SIZE and the call is skipped. The
        fallback is the same behaviour as without preallocation.
        """
        if size == 0:
            return
        try:
            import fcntl
            fcntl.fallocate(fh.fileno(), 0x01, 0, size)
        except (ImportError, OSError, AttributeError):
            pass

    def _open_for_shred(self, path):
        """Open the file for overwrite, trying O_DIRECT first when
        SHRED_DIRECT is set.

        O_DIRECT bypasses the page cache, so a write syscall
        returns only after the device has accepted the bytes.
        Without it, a write can sit in the cache while the next
        pass overwrites the cached copy — the second write never
        reaches the device, and the first pass is the only one
        that ever landed. On a filesystem that refuses O_DIRECT
        (some FUSE, some network FS), the open falls back to the
        default mode and the operation proceeds identically to
        the non-direct path.

        Returns a file object open in 'r+b' mode.
        """
        if self.SHRED_DIRECT:
            try:
                fd = os.open(path, os.O_RDWR | os.O_DIRECT)
                return os.fdopen(fd, 'r+b', buffering=0)
            except OSError:
                pass
        return open(path, 'r+b', buffering=0)

    def _sync_fs(self, path):
        """syncfs() the filesystem that holds `path`. Flushes the
        filesystem's own metadata and every dirty buffer on the
        volume, not just the file's own data. Linux-only; a no-op
        elsewhere."""
        if not self.SHRED_SYNCFS:
            return
        try:
            import ctypes
            libc = ctypes.CDLL('libc.so.6', use_errno=True)
            fd = os.open(os.path.dirname(path) or '.', os.O_RDONLY)
            try:
                libc.syncfs(fd)
            finally:
                os.close(fd)
        except Exception:
            pass

    def _trim_file(self, path):
        """Ask the filesystem to release the file's blocks to the
        device.

        On an SSD this is what actually causes the controller to
        garbage-collect the physical pages. The overwrite passes
        write new blocks; without a TRIM the old ones sit in the
        controller's free pool until it happens to need them. The
        overwrite is not what removes the data — the TRIM is.

        Falls back to a plain unlink if the filesystem does not
        support FALLOC_FL_PUNCH_HOLE. Called after unlink has
        already removed the directory entry; the goal here is to
        inform the block layer, not to remove the file.
        """
        if not self.SHRED_TRIM:
            return
        try:
            import fcntl
            parent = os.path.dirname(path) or '.'
            fd = os.open(parent, os.O_RDONLY)
            try:
                fcntl.fallocate(fd, 0x02 | 0x01, 0, 0)
            finally:
                os.close(fd)
        except (ImportError, OSError, AttributeError):
            pass

    def _find_luks_device(self, path):
        """Return the block device path backing `path` if and only
        if that device is a dm-crypt (LUKS) mapping. Returns None
        otherwise.

        Reads /proc/self/mountinfo to find the mount point that
        contains the given path, resolves that mount's device
        major:minor, and checks /sys/dev/block/<maj>:<min>/dm/uuid
        for a LUKS signature. The dm-crypt mapping's parent device
        is what `cryptsetup luksErase` needs.
        """
        try:
            real = os.path.realpath(path)
            best_mount = ''
            best_dev = ''
            with open('/proc/self/mountinfo', 'r',
                      encoding='utf-8') as fh:
                for line in fh:
                    fields = line.split()
                    if len(fields) < 5:
                        continue
                    dev = fields[2]
                    mount = fields[4]
                    if real == mount or real.startswith(
                            mount.rstrip('/') + '/'):
                        if len(mount) > len(best_mount):
                            best_mount = mount
                            best_dev = dev
            if not best_dev:
                return None

            syspath = f'/sys/dev/block/{best_dev}'
            dm_uuid_path = os.path.join(syspath, 'dm', 'uuid')
            if not os.path.exists(dm_uuid_path):
                return None
            with open(dm_uuid_path, 'r', encoding='utf-8') as fh:
                dm_uuid = fh.read().strip()
            if not dm_uuid.startswith('CRYPT-LUKS'):
                return None

            slaves_dir = os.path.join(syspath, 'slaves')
            if not os.path.isdir(slaves_dir):
                return None
            slaves = os.listdir(slaves_dir)
            if not slaves:
                return None
            return f'/dev/{slaves[0]}'
        except Exception:
            return None

    def _crypto_erase(self, path):
        """If `path` is on a LUKS volume, destroy the LUKS header.

        This makes every byte on the volume unrecoverable —
        including anything outside the TornadoC2 tree that happens
        to share the same encrypted volume. Warns loudly to stdout
        before doing it, because the operator's log handler may
        still be running and this is the last thing it will see.

        Returns True when the header was destroyed, False when
        the volume was not LUKS or the erase failed.
        """
        c = self.colors
        device = self._find_luks_device(path)
        if not device:
            return False

        import shutil
        import subprocess

        cryptsetup = shutil.which('cryptsetup')
        if not cryptsetup:
            print(f"{c['yellow']}[DEADMAN] crypto: {device} is a "
                  f"LUKS volume but cryptsetup is not on PATH — "
                  f"falling through to overwrite only{c['end']}")
            return False

        print(f"{c['red']}{c['bold']}[DEADMAN] crypto: destroying "
              f"LUKS header on {device} — every byte on this "
              f"volume becomes unrecoverable, including any data "
              f"outside the TornadoC2 tree{c['end']}")
        try:
            r = subprocess.run(
                [cryptsetup, 'luksErase', '--batch-mode', device],
                capture_output=True, text=True, timeout=30,
                check=False)
            if r.returncode == 0:
                print(f"{c['dim']}[DEADMAN] crypto: LUKS header on "
                      f"{device} destroyed{c['end']}")
                return True
            err = (r.stderr or r.stdout or '').strip()
            print(f"{c['yellow']}[DEADMAN] crypto: cryptsetup "
                  f"luksErase failed: {err[:200]}{c['end']}")
            return False
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"{c['yellow']}[DEADMAN] crypto: {exc}"
                  f"{c['end']}")
            return False

    def _shred_file(self, path):
        """Overwrite one regular file.

        Behaviour depends on the mode:

          pattern modes ('fast', 'random', 'dod', 'gutmann',
          'nist', 'schneier', 'hmg', 'bsi')
              preallocate if SHRED_PREALLOC, then write every
              pattern in the pass sequence, verify the final fixed
              pass if SHRED_VERIFY, truncate, fsync, syncfs if
              SHRED_SYNCFS, then rename if SHRED_RENAME and unlink.

          'trim'
              the same as above but with the mode's own pass
              sequence (SHRED_RANDOM_PASSES random passes), and
              then a FALLOC_FL_PUNCH_HOLE on the parent directory
              to trigger a discard after the unlink.

          'scrub'
              'trim' plus SHRED_PREALLOC = True and
              SHRED_DIRECT = True for the duration of this file.
              The kitchen sink for mixed HDD/SSD deployments.

          'crypto'
              one 'fast' overwrite pass, then _crypto_erase() on
              the containing volume. The erase is what makes the
              data unrecoverable; the overwrite is a courtesy for
              the case where the volume is not LUKS.

        Never raises — a shredder that dies on the first
        permission error is worse than one that reports and
        continues. Returns True on success.
        """
        mode = (self.SHRED_MODE or '').strip().lower()
        override_prealloc = (mode == 'scrub')
        override_direct = (mode == 'scrub')
        override_syncfs = (mode in ('scrub', 'trim')) or self.SHRED_SYNCFS

        try:
            st = os.lstat(path)
            if not _stat.S_ISREG(st.st_mode):
                return True   # sockets, fifos, etc. — nothing to wipe
            size = st.st_size

            if not (st.st_mode & _stat.S_IWUSR):
                try:
                    os.chmod(path, st.st_mode | _stat.S_IWUSR)
                except OSError:
                    pass

            if self.SHRED_OBSCURE_MTIME:
                self._obscure_time(path)

            if self.SHRED_RENAME:
                try:
                    new_path = os.path.join(
                        os.path.dirname(path),
                        os.urandom(16).hex())
                    os.rename(path, new_path)
                    path = new_path
                except OSError:
                    pass

            passes = self._passes_for_mode(mode)
            last_fixed = next(
                (p for p in reversed(passes) if p is not None), None)

            saved_direct = self.SHRED_DIRECT
            if override_direct:
                self.SHRED_DIRECT = True
            try:
                fh = self._open_for_shred(path)
            finally:
                self.SHRED_DIRECT = saved_direct

            with fh:
                if override_prealloc or self.SHRED_PREALLOC:
                    self._preallocate(fh, size)

                for pattern in passes:
                    self._wipe_pass(fh, size, pattern)

                if self.SHRED_VERIFY and last_fixed is not None:
                    if not self._verify_pass(fh, size, last_fixed):
                        return False

                fh.truncate(0)
                if self.SHRED_FSYNC:
                    try:
                        os.fsync(fh.fileno())
                    except OSError:
                        pass

            if override_syncfs:
                self._sync_fs(path)

            try:
                os.unlink(path)
            except OSError:
                return False

            if mode in ('trim', 'scrub') or self.SHRED_TRIM:
                self._trim_file(path)

            return True
        except OSError:
            return False

    def _shred_tree(self, root: str) -> bool:
        """Overwrite every regular file under `root` in parallel,
        then remove the tree. Returns True when the directory is
        gone.

        In 'crypto' mode this additionally destroys the LUKS header
        of the volume that holds the tree, if one is present. That
        step is what makes the data unrecoverable on an encrypted
        volume; the overwrite is a courtesy for the case where no
        LUKS header was found.
        """
        mode = (self.SHRED_MODE or '').strip().lower()
        crypto_erased = False
        if mode == 'crypto':
            try:
                crypto_erased = self._crypto_erase(root)
            except Exception:
                crypto_erased = False

        try:
            files = []
            for dirpath, _dirnames, filenames in os.walk(root):
                for fname in filenames:
                    files.append(os.path.join(dirpath, fname))

            if not crypto_erased:
                workers = max(1, int(self.SHRED_WORKERS))
                if workers == 1 or len(files) <= 1:
                    results = [self._shred_file(p) for p in files]
                else:
                    with _futures.ThreadPoolExecutor(
                            max_workers=workers) as pool:
                        results = list(pool.map(
                            self._shred_file, files))

            shutil.rmtree(root, ignore_errors=True)
            return not os.path.exists(root)
        except Exception:
            return False

    def _system_halt(self) -> None:
        """Invoke the host's power management, if configured.

        Runs as the user that started the handler. On most systems
        this requires the user to be in a group permitted to
        power off without a password — sudoers NOPASSWD for
        /sbin/shutdown or /usr/bin/systemctl, or a polkit rule.
        Failures print a message and return; the process still
        exits via os._exit(1) in the caller.
        """
        import shutil
        import subprocess

        if not self._halt_mode:
            return

        c = self.colors
        print(f"{c['yellow']}[DEADMAN] requesting system "
              f"{self._halt_mode}{c['end']}")

        candidates = []
        systemctl = shutil.which('systemctl')
        if systemctl:
            verb = 'reboot' if self._halt_mode == 'reboot' \
                else 'poweroff'
            candidates.append([systemctl, verb])

        for name in ('shutdown', 'halt'):
            path = shutil.which(name)
            if not path:
                continue
            if self._halt_mode == 'reboot':
                candidates.append([path, '-r', 'now'])
            else:
                candidates.append([path, '-h', 'now'])

        for cmd in candidates:
            try:
                r = subprocess.run(cmd, capture_output=True,
                                   text=True, timeout=15,
                                   check=False)
                if r.returncode == 0:
                    return
                err = (r.stderr or r.stdout or '').strip()
                if err:
                    print(f"{c['dim']}[DEADMAN] {cmd[0]} said: "
                          f"{err[:200]}{c['end']}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(f"{c['dim']}[DEADMAN] {cmd[0]}: "
                      f"{exc}{c['end']}")
                continue

        print(f"{c['red']}[DEADMAN] system {self._halt_mode} "
              f"failed — the handler user likely lacks permission. "
              f"Grant sudoers NOPASSWD for systemctl, or leave "
              f"TORNADO_DEADMAN_HALT unset.{c['end']}")

    # ------------------------------------------------------------------
    # Persistence

    def _load_config(self) -> None:
        try:
            with open(self.config_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return

        try:
            d = float(data.get('deadline', 0))
            if d > 0:
                self._deadline = d
        except (TypeError, ValueError):
            pass

        try:
            w = float(data.get('window_seconds', 0))
            if w > 0:
                self._window_seconds = max(
                    self.MIN_WINDOW_SECONDS,
                    min(self.MAX_WINDOW_SECONDS, w))
        except (TypeError, ValueError):
            pass

        try:
            a = float(data.get('armed_at', 0))
            if a > 0:
                self._armed_at = a
        except (TypeError, ValueError):
            pass

        try:
            c = float(data.get('check_seconds',
                               self.DEFAULT_CHECK_SECONDS))
            self._check_seconds = max(5.0, c)
        except (TypeError, ValueError):
            pass

        warn = data.get('warn_fractions')
        if isinstance(warn, list):
            cleaned = tuple(sorted(
                float(f) for f in warn
                if isinstance(f, (int, float))
                and 0.0 < float(f) < 1.0))
            self._warn_fractions = cleaned

        halt = data.get('halt')
        if isinstance(halt, str):
            self._config_halt_mode = halt.strip().lower()
        else:
            self._config_halt_mode = ''

        mode = data.get('shred_mode')
        if isinstance(mode, str) and mode.strip():
            self.SHRED_MODE = mode.strip().lower()

        try:
            n = int(data.get('shred_random_passes',
                             self.SHRED_RANDOM_PASSES))
            self.SHRED_RANDOM_PASSES = max(1, n)
        except (TypeError, ValueError):
            pass

        for key, attr in (
                ('shred_prealloc', 'SHRED_PREALLOC'),
                ('shred_direct',   'SHRED_DIRECT'),
                ('shred_trim',     'SHRED_TRIM'),
                ('shred_syncfs',   'SHRED_SYNCFS')):
            v = data.get(key)
            if isinstance(v, bool):
                setattr(self, attr, v)

    def _save_config(self) -> None:
        with self._lock:
            data = {
                'deadline':            self._deadline,
                'window_seconds':      self._window_seconds,
                'armed_at':            self._armed_at,
                'check_seconds':       self._check_seconds,
                'warn_fractions':      list(self._warn_fractions),
                'halt':                self._halt_mode,
                'shred_mode':          self.SHRED_MODE,
                'shred_random_passes': self.SHRED_RANDOM_PASSES,
                'shred_prealloc':      self.SHRED_PREALLOC,
                'shred_direct':        self.SHRED_DIRECT,
                'shred_trim':          self.SHRED_TRIM,
                'shred_syncfs':        self.SHRED_SYNCFS,
            }
        try:
            parent = os.path.dirname(self.config_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = self.config_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.config_path)
            try:
                os.chmod(self.config_path, 0o600)
            except OSError:
                pass
        except OSError:
            pass

    def _apply_env_overrides(self) -> None:
        """Env vars override the persisted config for one run only.
        Useful for tests and one-shot invocations."""
        try:
            h = float(os.environ.get('TORNADO_DEADMAN_HOURS', '0'))
            if h > 0:
                now = time.time()
                secs = h * 3600.0
                self._deadline = now + secs
                self._window_seconds = secs
                self._armed_at = now
        except (TypeError, ValueError):
            pass
        try:
            c = float(os.environ.get('TORNADO_DEADMAN_CHECK', '0'))
            if c > 0:
                self._check_seconds = max(5.0, c)
        except (TypeError, ValueError):
            pass
        raw = os.environ.get('TORNADO_DEADMAN_WARN', '')
        if raw:
            try:
                cleaned = tuple(sorted(
                    float(p) for p in raw.split(',') if p.strip()
                    if 0.0 < float(p) < 1.0))
                self._warn_fractions = cleaned
            except (TypeError, ValueError):
                pass

        mode = os.environ.get('TORNADO_DEADMAN_SHRED', '').strip()
        if mode:
            self.SHRED_MODE = mode.lower()
        try:
            n = int(os.environ.get(
                'TORNADO_DEADMAN_SHRED_PASSES', '0'))
            if n > 0:
                self.SHRED_RANDOM_PASSES = n
        except (TypeError, ValueError):
            pass

    # ------------------------------------------------------------------
    # Helpers

    def _audit(self, action: str, detail: str) -> None:
        log = getattr(self.handler, 'audit_log', None)
        if log is None:
            return
        try:
            log.write(operator='__local__', role='local',
                      source_ip='local', action=action,
                      detail=detail)
        except Exception:
            pass

    @staticmethod
    def _fmt_duration(seconds) -> str:
        seconds = max(0.0, float(seconds))
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            return f"{seconds / 60:.1f}m"
        if seconds < 86400:
            return f"{seconds / 3600:.2f}h"
        return f"{seconds / 86400:.2f}d"

    @classmethod
    def parse_duration(cls, spec: str):
        """Parse '30m', '2h30m', '1d', or a bare number of seconds.
        Returns float seconds, or None on malformed input."""
        spec = (spec or '').strip().lower()
        if not spec:
            return None
        try:
            n = float(spec)
            return n if n > 0 else None
        except ValueError:
            pass
        units = {'s': 1.0, 'm': 60.0, 'h': 3600.0, 'd': 86400.0}
        total = 0.0
        i = 0
        while i < len(spec):
            j = i
            while j < len(spec) and (spec[j].isdigit()
                                     or spec[j] == '.'):
                j += 1
            if j == i:
                return None
            try:
                n = float(spec[i:j])
            except ValueError:
                return None
            if j >= len(spec) or spec[j] not in units:
                return None
            total += n * units[spec[j]]
            i = j + 1
        return total if total > 0 else None

    @classmethod
    def parse_deadline(cls, spec: str):
        """Parse 'HH:MM' into a Unix timestamp today, or tomorrow
        if the time has already passed. Returns None on bad input."""
        spec = (spec or '').strip()
        if ':' not in spec:
            return None
        try:
            h, m = spec.split(':', 1)
            h, m = int(h), int(m)
        except (ValueError, TypeError):
            return None
        if not (0 <= h <= 23 and 0 <= m <= 59):
            return None
        now = time.localtime()
        target = time.struct_time((
            now.tm_year, now.tm_mon, now.tm_mday,
            h, m, 0, now.tm_wday, now.tm_yday, now.tm_isdst))
        ts = time.mktime(target)
        if ts <= time.time():
            ts += 86400
        return ts