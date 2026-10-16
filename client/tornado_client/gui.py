"""PySide6 operator console for TornadoC2.

Same contract as the Tkinter version:

  * The CLI (``tornado_client.repl``) is the backend. This module
    never re-implements protocol logic — it constructs the same
    ``Client`` instance and dispatches every command through the
    same ``Client._cmd_*`` methods.

  * Three substitutions make the GUI transparent to ``repl``:

        1. ``sys.stdout`` / ``sys.stderr``  →  ``_GuiStream`` (queue)
        2. ``builtins.input``               →  modal QDialog
        3. ``getpass.getpass``              →  masked modal QDialog

    Because the swap happens *before* ``repl`` is imported,
    ``repl._COLOR`` is False and the ``CLR`` dict is all empty
    strings — the GUI receives clean plaintext.

  * Chat runs as a persistent session independent of the command
    worker. ``_GuiChat`` starts a long-poll thread at GUI startup;
    messages land in the Chat tab regardless of which tab is active.
    The CLI's synchronous ``_cmd_chat`` is never invoked.

Qt-specific notes:

  * The theme is dark, GitHub-dark-inspired, and lives entirely in
    the ``Palette`` class. Every QSS rule and every widget call
    site references a ``Palette`` name — a hard-coded hex value
    outside that class is a bug, because it will survive a theme
    change and stick out. The five chat speaker colours are the
    one exception: they are generated per-operator by
    ``_chat_hue`` and tuned against the dark ``Palette.BG``
    surface in ``_CHAT_HUES``.

  * ``QApplication`` must exist before any ``QWidget``. ``main_gui``
    therefore creates the app, sets the theme, then constructs the
    transport (whose ``__init__`` may prompt via ``getpass``), then
    constructs the main window.

  * Cross-thread calls do NOT use ``QTimer.singleShot``. From a
    worker thread that fires in the *calling* thread; use a ``Signal``
    instead — Qt queues the slot to the receiver's thread.

  * The log and chat views use ``QPlainTextEdit`` with a
    ``QTextCursor`` + ``QTextCharFormat``. ``setMaximumBlockCount``
    replaces the manual 50k-line trim of the Tk version.
"""

from __future__ import annotations

import argparse
import base64 as _b64
import builtins
import getpass as _getpass_mod
import hashlib
import io
import json
import os
import queue
import re
import secrets as _secrets
import sys
import threading
import time
from typing import Optional

# ── Platform selection ────────────────────────────────────────
if os.environ.get('WAYLAND_DISPLAY'):
    os.environ.setdefault('QT_QPA_PLATFORM', 'wayland;xcb')
elif os.environ.get('DISPLAY'):
    os.environ.setdefault('QT_QPA_PLATFORM', 'xcb')

# ── GL backend selection ──────────────────────────────────────
os.environ.setdefault('LIBGL_ALWAYS_SOFTWARE', '1')

from PySide6.QtCore import (
    QEvent, QObject, QPoint, QSize, Qt, QTimer, Signal, Slot,
)
from PySide6.QtGui import (
    QAction, QBrush, QColor, QFont, QFontDatabase, QIcon,
    QKeySequence, QPainter, QShortcut, QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFormLayout, QFrame, QGridLayout, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMenu, QMenuBar,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea,
    QSizePolicy, QSplitter, QStackedWidget, QStatusBar, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)


# ---------------------------------------------------------------------
# Palette

class Palette:
    """GitHub-dark-inspired palette.

    Every QSS rule and every widget call site references a name
    on this class, so the theme is defined here and nowhere else.
    A widget that hard-codes a hex value outside this class will
    be out of place after a theme change — keep the palette the
    single source of truth.
    """

    # ── Surfaces ──────────────────────────────────────────
    # BG is the main window and dialog background.
    # BG_APP is the sidebar, which sits a shade darker for
    #   visual separation.
    # BG_PANEL is the tab pane — same as BG, so tabs feel like
    #   they extend the main canvas.
    # BG_SOFT is used for inline "quiet" regions: read-only
    #   field fills, disabled button backgrounds, the input-bar
    #   container when unfocused.
    # BG_INPUT is the fill of actual text inputs, combo boxes,
    #   and the main input bar.
    # BG_SELECT is the tree / list / combo selection highlight.
    # BG_HOVER is the hover state for tree rows and menu items.
    BG            = '#0d1117'
    BG_APP        = '#010409'
    BG_PANEL      = '#0d1117'
    BG_SOFT       = '#161b22'
    BG_INPUT      = '#0d1117'
    BG_SELECT     = '#1f3a5f'
    BG_HOVER      = '#161b22'

    # ── Header bar ────────────────────────────────────────
    # Deliberately darker than the app body so the brand strip
    # reads as a top rail rather than another panel.
    HEADER_BG      = '#010409'
    HEADER_FG      = '#e6edf3'
    HEADER_MUTED   = '#7d8590'
    HEADER_DIVIDER = '#30363d'

    # ── Borders ───────────────────────────────────────────
    # Three weights, all dim enough to sit on a dark surface
    # without becoming visual noise. STRONG is reserved for
    # hover states on scrollbars and splitter handles.
    BORDER        = '#30363d'
    BORDER_SOFT   = '#21262d'
    BORDER_STRONG = '#6e7681'

    # ── Text ──────────────────────────────────────────────
    # TEXT is the default foreground for log lines and body
    # copy. TEXT_MUTED is for labels and secondary information.
    # TEXT_FAINT is for hints and metadata.
    # TEXT_INVERT stays light: it is the color of text on the
    # accent-colored primary button and on selection highlight
    # bands, both of which are coloured.
    TEXT          = '#e6edf3'
    TEXT_MUTED    = '#8b949e'
    TEXT_FAINT    = '#6e7681'
    TEXT_INVERT   = '#ffffff'

    # ── Accent ────────────────────────────────────────────
    # ACCENT is the primary interactive colour — focus rings,
    # selected tabs, the prompt glyph.
    # ACCENT_HI is the higher-contrast variant used as text on
    # an ACCENT_SOFT background (role badge, topic banner,
    # summary strip).
    # ACCENT_SOFT is the dark-navy fill those tinted regions
    # use. It is a solid colour rather than an rgba tint so the
    # same value renders identically on every Qt platform
    # plugin; the visual effect is close enough.
    # ACCENT_FAINT is the border on top of ACCENT_SOFT.
    ACCENT        = '#58a6ff'
    ACCENT_HI     = '#79c0ff'
    ACCENT_SOFT   = '#0d2247'
    ACCENT_FAINT  = '#1f6feb'

    # ── Status ────────────────────────────────────────────
    # OK / WARN / ERR are the foreground shades for success,
    # warning, and error text. The _BG variants are the fill
    # colours for badges and inline notices; the _BORDER
    # variants are the outline. All three are used together,
    # never independently.
    OK            = '#3fb950';  OK_BG     = '#0f2417';  OK_BORDER     = '#1a7f37'
    WARN          = '#d29922';  WARN_BG   = '#2d2212';  WARN_BORDER   = '#9a6700'
    ERR           = '#f85149';  ERR_BG    = '#2d0e0e';  ERR_BORDER    = '#cf222e'
    PURPLE        = '#bc8cff';  PURPLE_BG = '#1c1530'
    CYAN          = '#58a6ff'
    MAGENTA       = '#db61a2'


class Sp:
    XS = 4
    S  = 8
    M  = 12
    L  = 16
    XL = 24


# ---------------------------------------------------------------------
# Fonts

_FONTS: dict = {}
_MONO_FONT: QFont = None
_UI_FONT: QFont = None


def _resolve_fonts() -> None:
    """Populate _FONTS using the running QApplication's font database.
    Must be called after QApplication exists."""
    global _MONO_FONT, _UI_FONT
    families = set(QFontDatabase.families())

    def pick(*cands, default):
        for c in cands:
            if c in families:
                return c
        return default

    _FONTS['ui'] = pick(
        'Inter', 'Segoe UI', 'SF Pro Text', 'Helvetica Neue',
        'DejaVu Sans', 'Liberation Sans', 'Arial',
        default='sans-serif')
    _FONTS['mono'] = pick(
        'JetBrains Mono', 'Cascadia Mono', 'SF Mono', 'Menlo',
        'Consolas', 'DejaVu Sans Mono', 'Liberation Mono',
        'Courier New',
        default='monospace')
    _UI_FONT = QFont(_FONTS['ui'], 10)
    _MONO_FONT = QFont(_FONTS['mono'], 10)


def _f_ui(size: int = 10, bold: bool = False) -> QFont:
    f = QFont(_FONTS.get('ui', 'sans-serif'), size)
    if bold:
        f.setWeight(QFont.Weight.Bold)
    return f


def _f_mono(size: int = 10, bold: bool = False) -> QFont:
    f = QFont(_FONTS.get('mono', 'monospace'), size)
    if bold:
        f.setWeight(QFont.Weight.Bold)
    return f


# ---------------------------------------------------------------------
# QSS — the whole look lives here

STYLESHEET = f"""
* {{
    font-family: "__UI_FONT__";
    font-size: 10pt;
    color: {Palette.TEXT};
    outline: 0;
}}
QMainWindow, QDialog {{ background: {Palette.BG}; }}

/* ── Header ───────────────────────────────────────────── */
QWidget#headerBar {{ background: {Palette.HEADER_BG}; }}
QWidget#headerDivider {{ background: {Palette.HEADER_DIVIDER}; }}
QLabel#brandWord  {{
    color: {Palette.HEADER_FG};
    font-weight: 700;
    font-size: 11pt;
    letter-spacing: 0.6px;
}}
QLabel#brandSub {{
    color: {Palette.HEADER_MUTED};
    font-size: 9pt;
    letter-spacing: 0.4px;
}}
QLabel#brandGlyph {{
    color: {Palette.ACCENT};
    font-weight: 700;
    font-size: 14pt;
}}
QLabel#connInfo {{
    color: {Palette.HEADER_MUTED};
    font-family: "__MONO_FONT__";
    font-size: 9pt;
}}
QLabel#roleBadge {{
    background: {Palette.ACCENT_SOFT};
    color: {Palette.ACCENT_HI};
    font-weight: 700;
    font-size: 9pt;
    padding: 3px 10px;
    border-radius: 9px;
}}
QLabel#statusPill {{
    color: {Palette.HEADER_MUTED};
    font-weight: 700;
    font-size: 9pt;
}}
QLabel#statusPill[state="online"]  {{ color: {Palette.OK}; }}
QLabel#statusPill[state="offline"] {{ color: {Palette.ERR}; }}

/* ── Sidebar ──────────────────────────────────────────── */
QWidget#sidebar {{
    background: {Palette.BG_SOFT};
    border-bottom: 1px solid {Palette.BORDER_SOFT};
}}
QLabel#sectionLabel {{
    color: {Palette.TEXT_MUTED};
    font-weight: 700;
    font-size: 9pt;
    letter-spacing: 1.0px;
}}
QLabel#sectionCount {{
    color: {Palette.TEXT_FAINT};
    font-family: "__MONO_FONT__";
    font-size: 9pt;
}}

/* ── Inputs ───────────────────────────────────────────── */
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox {{
    background: {Palette.BG_INPUT};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 6px;
    padding: 5px 9px;
    selection-background-color: {Palette.ACCENT};
    selection-color: {Palette.TEXT_INVERT};
}}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
    border-color: {Palette.ACCENT};
}}
QLineEdit[readOnly="true"] {{ color: {Palette.TEXT_MUTED}; }}
QComboBox::drop-down {{
    border: none;
    width: 22px;
    padding-right: 6px;
}}
QComboBox QAbstractItemView {{
    background: {Palette.BG_PANEL};
    border: 1px solid {Palette.BORDER};
    selection-background-color: {Palette.BG_SELECT};
    selection-color: {Palette.TEXT};
    padding: 4px;
    outline: 0;
}}

/* ── Buttons ──────────────────────────────────────────── */
QPushButton {{
    background: {Palette.BG_PANEL};
    color: {Palette.TEXT};
    border: 1px solid {Palette.BORDER};
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 500;
    min-height: 20px;
}}
QPushButton:hover   {{ background: {Palette.BG_HOVER}; }}
QPushButton:pressed {{ background: {Palette.BG_SOFT}; }}
QPushButton:focus   {{ border-color: {Palette.ACCENT}; }}
QPushButton:disabled {{
    background: {Palette.BG_SOFT};
    color: {Palette.TEXT_FAINT};
    border-color: {Palette.BORDER_SOFT};
}}
QPushButton#primary {{
    background: {Palette.ACCENT};
    color: {Palette.TEXT_INVERT};
    border: 1px solid {Palette.ACCENT_HI};
    font-weight: 600;
    padding: 6px 18px;
}}
QPushButton#primary:hover   {{ background: {Palette.ACCENT_HI}; }}
QPushButton#primary:pressed {{ background: {Palette.ACCENT_HI}; }}
QPushButton#ghost {{
    background: transparent;
    border: none;
    color: {Palette.TEXT_MUTED};
    padding: 4px 8px;
    font-size: 9pt;
}}
QPushButton#ghost:hover {{
    background: {Palette.BG_HOVER};
    color: {Palette.TEXT};
    border-radius: 4px;
}}

/* ── Tree (beacon list) ───────────────────────────────── */
QTreeWidget {{
    background: {Palette.BG_PANEL};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 6px;
    outline: 0;
    alternate-background-color: {Palette.BG_PANEL};
    padding: 4px 0;
}}
QTreeWidget::item {{
    padding: 9px 6px;
    border: none;
    border-bottom: 1px solid {Palette.BORDER_SOFT};
    color: {Palette.TEXT};
}}
QTreeWidget::item:selected {{
    background: {Palette.BG_SELECT};
    color: {Palette.TEXT};
}}
QTreeWidget::item:hover {{
    background: {Palette.BG_HOVER};
}}
QHeaderView {{
    background: {Palette.BG_SOFT};
}}
QHeaderView::section {{
    background: {Palette.BG_SOFT};
    color: {Palette.TEXT_FAINT};
    border: none;
    border-bottom: 1px solid {Palette.BORDER};
    padding: 8px 8px;
    font-weight: 700;
    font-size: 8.5pt;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}}
QHeaderView::section:hover {{ color: {Palette.TEXT}; }}

/* ── Tabs ─────────────────────────────────────────────── */
QTabWidget::pane {{
    border: none;
    background: {Palette.BG_PANEL};
    top: -1px;
}}
QTabWidget::tab-bar {{ left: 0px; }}
QTabBar {{ qproperty-drawBase: 0; }}
QTabBar::tab {{
    background: transparent;
    color: {Palette.TEXT_MUTED};
    padding: 10px 20px;
    font-weight: 600;
    font-size: 10pt;
    border: none;
    border-bottom: 2px solid transparent;
    margin-right: 4px;
}}
QTabBar::tab:selected {{
    color: {Palette.ACCENT};
    border-bottom: 2px solid {Palette.ACCENT};
}}
QTabBar::tab:hover:!selected {{
    color: {Palette.TEXT};
    border-bottom: 2px solid {Palette.BORDER};
}}

/* ── Text views ───────────────────────────────────────── */
QPlainTextEdit#logView, QPlainTextEdit#chatView {{
    background: {Palette.BG_PANEL};
    border: none;
    border-radius: 0;
    padding: 12px 16px;
    font-family: "__MONO_FONT__";
    font-size: 10pt;
}}

/* ── Scrollbars ───────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {Palette.BORDER_SOFT};
    border-radius: 5px;
    min-height: 32px;
}}
QScrollBar::handle:vertical:hover {{ background: {Palette.BORDER_STRONG}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}
QScrollBar::handle:horizontal {{
    background: {Palette.BORDER_SOFT};
    border-radius: 5px;
    min-width: 32px;
}}
QScrollBar::handle:horizontal:hover {{ background: {Palette.BORDER_STRONG}; }}

/* ── Menus ────────────────────────────────────────────── */
QMenuBar {{
    background: {Palette.BG_PANEL};
    color: {Palette.TEXT};
    border-bottom: 1px solid {Palette.BORDER_SOFT};
    padding: 2px 4px;
}}
QMenuBar::item {{
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}}
QMenuBar::item:selected {{
    background: {Palette.BG_HOVER};
}}
QMenu {{
    background: {Palette.BG_PANEL};
    border: 1px solid {Palette.BORDER};
    border-radius: 6px;
    padding: 6px;
}}
QMenu::item {{
    padding: 6px 24px 6px 20px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background: {Palette.ACCENT};
    color: {Palette.TEXT_INVERT};
}}
QMenu::separator {{
    height: 1px;
    background: {Palette.BORDER_SOFT};
    margin: 4px 8px;
}}

/* ── Status bar ───────────────────────────────────────── */
QStatusBar {{
    background: {Palette.BG_APP};
    color: {Palette.TEXT_MUTED};
    border-top: 1px solid {Palette.BORDER_SOFT};
    font-family: "__MONO_FONT__";
    font-size: 9pt;
}}
QStatusBar::item {{ border: none; }}

/* ── Splitter handle ──────────────────────────────────── */
QSplitter::handle {{
    background: {Palette.BORDER_SOFT};
    width: 1px;
}}

/* ── Tooltips ─────────────────────────────────────────── */
QToolTip {{
    background: {Palette.HEADER_BG};
    color: {Palette.HEADER_FG};
    border: 1px solid {Palette.HEADER_DIVIDER};
    padding: 6px 10px;
    border-radius: 4px;
}}

/* ── Search field container ───────────────────────────── */
QWidget#searchBox {{
    background: {Palette.BG_INPUT};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 6px;
}}
QWidget#searchBox[focused="true"] {{
    border-color: {Palette.ACCENT};
}}
QWidget#searchBox QLineEdit {{
    border: none;
    background: transparent;
    padding: 4px 2px;
}}
QWidget#searchBox QLabel {{
    color: {Palette.TEXT_FAINT};
    background: transparent;
    padding: 0 4px 0 8px;
}}

/* ── Input bar ────────────────────────────────────────── */
QWidget#inputBar {{
    background: {Palette.BG_INPUT};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 8px;
}}
QWidget#inputBar[focused="true"] {{
    border-color: {Palette.ACCENT};
}}
QWidget#inputBar QLabel {{
    background: transparent;
}}
QWidget#inputBar QLineEdit {{
    border: none;
    background: transparent;
    padding: 8px 4px;
}}

/* ── Chat topic banner ────────────────────────────────── */
QWidget#chatTopic {{
    background: {Palette.ACCENT_SOFT};
    border-bottom: 1px solid {Palette.ACCENT_FAINT};
}}
QWidget#chatTopic QLabel {{
    background: transparent;
    color: {Palette.ACCENT_HI};
    font-size: 9pt;
}}

/* ── Build dialog ─────────────────────────────────────── */
QLabel#formHeading {{
    color: {Palette.TEXT_FAINT};
    font-weight: 700;
    font-size: 9pt;
    letter-spacing: 0.8px;
    padding-top: 14px;
    padding-bottom: 2px;
}}
QLabel#formLabel {{
    color: {Palette.TEXT_MUTED};
    font-size: 9pt;
}}
QLabel#formHint {{
    color: {Palette.TEXT_FAINT};
    font-size: 8.5pt;
    padding-bottom: 6px;
}}
QLabel#breadcrumb {{
    color: {Palette.TEXT_MUTED};
    font-family: "__MONO_FONT__";
    font-size: 9pt;
    padding: 6px 12px;
    background: {Palette.BG_SOFT};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 4px;
}}
QLabel#summaryStrip {{
    color: {Palette.ACCENT_HI};
    font-family: "__MONO_FONT__";
    font-size: 9pt;
    padding: 8px 12px;
    background: {Palette.ACCENT_SOFT};
    border: 1px solid {Palette.ACCENT_FAINT};
    border-radius: 6px;
}}
QLabel#dlgHeader {{
    font-weight: 700;
    font-size: 14pt;
}}
QLabel#dlgSub {{
    color: {Palette.TEXT_MUTED};
    font-size: 9pt;
}}
"""


# ---------------------------------------------------------------------
# Text helpers

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub('', s)


def _chat_day_label(ts: float) -> str:
    import datetime as _dt
    d = _dt.date.fromtimestamp(ts)
    today = _dt.date.today()
    if d == today:
        return 'TODAY'
    if d == today - _dt.timedelta(days=1):
        return 'YESTERDAY'
    return d.strftime('%A %d %B %Y').upper()


# Speaker colours for chat. Indexed by a stable hash of the
# operator name, so the same operator always renders in the same
# colour on every client. Values are tuned for the dark surface
# in Palette — light enough to read against #0d1117, saturated
# enough to be distinguishable from each other at a glance.
_CHAT_HUES = ('#58a6ff', '#3fb950', '#d29922', '#bc8cff', '#db61a2')


def _chat_hue(name: str) -> str:
    if not name:
        return _CHAT_HUES[0]
    h = 0
    for ch in name:
        h = (h * 31 + ord(ch)) & 0xffffffff
    return _CHAT_HUES[h % len(_CHAT_HUES)]


def _human_bytes(n: int) -> str:
    for unit in ('B', 'K', 'M', 'G'):
        if n < 1024:
            if unit == 'B':
                return f"{n}B"
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


def _make_fmt(color: str, font: Optional[QFont] = None,
              italic: bool = False, bold: bool = False
              ) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if font is not None:
        f.setFont(font)
    if italic:
        f.setFontItalic(True)
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    return f


# ---------------------------------------------------------------------
# stdout bridge

class _GuiStream(io.TextIOBase):
    """sys.stdout replacement that pushes complete lines onto a queue."""

    def __init__(self, q: "queue.Queue[tuple]") -> None:
        super().__init__()
        self._q = q
        self._lock = threading.Lock()
        self._buf = ''

    def write(self, s: str) -> int:
        if not s:
            return 0
        with self._lock:
            self._buf += s
            while True:
                nl = self._buf.find('\n')
                cr = self._buf.find('\r')
                if nl == -1 and cr == -1:
                    break
                if nl == -1:
                    idx, kind = cr, 'cr'
                elif cr == -1:
                    idx, kind = nl, 'nl'
                else:
                    idx = min(nl, cr)
                    kind = 'nl' if idx == nl else 'cr'
                line = self._buf[:idx]
                rest = self._buf[idx + 1:]
                if kind == 'cr' and rest.startswith('\n'):
                    kind = 'nl'
                    rest = rest[1:]
                self._buf = rest
                if kind == 'cr' and not line:
                    continue
                self._q.put(('out', line, kind))
        return len(s)

    def flush(self) -> None:
        with self._lock:
            if self._buf:
                self._q.put(('out', self._buf, 'cr'))
                self._buf = ''

    def isatty(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False


# ---------------------------------------------------------------------
# Small custom widgets

class StatusDot(QWidget):
    """A 10×10 filled circle whose color reflects connection state."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedSize(10, 10)
        self._color = QColor(Palette.HEADER_MUTED)

    def set_color(self, hexcolor: str) -> None:
        self._color = QColor(hexcolor)
        self.update()

    def paintEvent(self, _ev: QEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(self._color))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(0, 0, 10, 10)


class _HistoryLineEdit(QLineEdit):
    """QLineEdit with Up/Down bound to a command history list."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._history: list[str] = []
        self._idx: int = 0

    def set_history(self, history: list[str]) -> None:
        self._history = history

    def reset_cursor(self) -> None:
        self._idx = len(self._history)

    def keyPressEvent(self, ev) -> None:
        key = ev.key()
        if key == Qt.Key.Key_Up and self._history:
            self._idx = max(0, self._idx - 1)
            self.setText(self._history[self._idx])
            self.setCursorPosition(len(self.text()))
            return
        if key == Qt.Key.Key_Down and self._history:
            self._idx = min(len(self._history), self._idx + 1)
            if self._idx >= len(self._history):
                self.setText('')
            else:
                self.setText(self._history[self._idx])
            self.setCursorPosition(len(self.text()))
            return
        super().keyPressEvent(ev)


class _FocusFrame(QFrame):
    """A QFrame that toggles a `focused` dynamic property on focus
    so QSS can brighten the border. Used by the search box and the
    input bar. Focus lands on a child, so we install an event filter
    and re-polish the parent."""

    def __init__(self, child_focus_widget: QWidget,
                 parent: Optional[QWidget] = None,
                 name: str = 'focusFrame') -> None:
        super().__init__(parent)
        self.setObjectName(name)
        self.setProperty('focused', False)
        child_focus_widget.installEventFilter(self)

    def eventFilter(self, obj, ev):
        if ev.type() == QEvent.Type.FocusIn:
            self.setProperty('focused', True)
            self.style().unpolish(self)
            self.style().polish(self)
        elif ev.type() == QEvent.Type.FocusOut:
            self.setProperty('focused', False)
            self.style().unpolish(self)
            self.style().polish(self)
        return super().eventFilter(obj, ev)




class _BeaconTree(QTreeWidget):
    """QTreeWidget that paints a centered hint when empty.

    The plain QTreeWidget shows a blank pane when there are no
    beacons, which reads as a broken widget rather than a
    waiting state. Painting the hint in the viewport's paint
    event keeps it aligned to the scroll area rather than to
    the widget's full rect (which includes the header bar), so
    the text sits visually centered in the empty region.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._empty_text = ''

    def set_empty_text(self, text: str) -> None:
        if text != self._empty_text:
            self._empty_text = text
            self.viewport().update()

    def paintEvent(self, ev) -> None:
        super().paintEvent(ev)
        if self.topLevelItemCount() != 0 or not self._empty_text:
            return
        p = QPainter(self.viewport())
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        p.setPen(QColor(Palette.TEXT_FAINT))
        f = self.font()
        f.setItalic(True)
        p.setFont(f)
        p.drawText(
            self.viewport().rect(),
            Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
            self._empty_text,
        )


# ---------------------------------------------------------------------
# Early getpass — QApplication must already exist when this runs

def _early_getpass(prompt: str = 'Password: ') -> str:
    """Stand-in for getpass.getpass used before GuiApp exists.

    Transport.__init__ prompts for the operator password when the
    config carries password_required: true. That happens in
    main_gui before GuiApp is constructed — and before GuiApp's
    normal getpass interceptor is installed. The stdlib falls back
    to reading stdin, which silently produces no password under a
    GUI launch.

    This helper assumes QApplication is already running (see
    main_gui) so it can show a proper QDialog. It raises EOFError
    on cancel so the caller's except around Transport(cfg) fires
    with a clear failure rather than proceeding with an empty
    password.
    """
    prompt = _strip_ansi(prompt).strip() or 'Password:'
    dlg = QDialog()
    dlg.setWindowTitle('Operator password')
    dlg.setModal(True)
    dlg.setMinimumWidth(460)

    outer = QVBoxLayout(dlg)
    outer.setContentsMargins(22, 20, 22, 18)
    outer.setSpacing(6)

    title = QLabel(prompt)
    title.setFont(_f_ui(12, bold=True))
    outer.addWidget(title)

    hint = QLabel(
        'This operator carries a password second factor. The '
        'client derives the HMAC key from it and signs every '
        'request with that key. The password is not stored on '
        'disk.')
    hint.setFont(_f_ui(9))
    hint.setStyleSheet(f'color: {Palette.TEXT_MUTED};')
    hint.setWordWrap(True)
    outer.addWidget(hint)
    outer.addSpacing(10)

    entry = QLineEdit()
    entry.setEchoMode(QLineEdit.EchoMode.Password)
    entry.setFont(_f_ui(11))
    entry.setMinimumHeight(32)
    outer.addWidget(entry)
    outer.addSpacing(12)

    btns = QHBoxLayout()
    btns.addStretch(1)
    cancel = QPushButton('Cancel')
    cancel.setMinimumWidth(80)
    ok = QPushButton('OK')
    ok.setObjectName('primary')
    ok.setMinimumWidth(80)
    ok.setDefault(True)
    btns.addWidget(cancel)
    btns.addWidget(ok)
    outer.addLayout(btns)

    result = {'ok': False}

    def _accept():
        result['ok'] = True
        dlg.accept()

    def _reject():
        result['ok'] = False
        dlg.reject()

    cancel.clicked.connect(_reject)
    ok.clicked.connect(_accept)
    entry.returnPressed.connect(_accept)

    entry.setFocus()
    dlg.exec()

    if not result['ok'] or not entry.text():
        raise EOFError
    return entry.text()


# ---------------------------------------------------------------------
# Dialogs

class _InputPrompt(QDialog):
    """Modal single-line text prompt. Used for CLI confirmations."""

    def __init__(self, parent: QWidget, prompt: str,
                 mask: bool = False, title: str = 'Input') -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(500)
        self.result: Optional[str] = None

        prompt = _strip_ansi(prompt).strip() or 'Input:'
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 18, 20, 16)
        outer.setSpacing(10)

        lbl = QLabel(prompt)
        lbl.setWordWrap(True)
        outer.addWidget(lbl)

        self._entry = QLineEdit()
        self._entry.setMinimumHeight(30)
        if mask:
            self._entry.setEchoMode(QLineEdit.EchoMode.Password)
        outer.addWidget(self._entry)

        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = QPushButton('Cancel')
        cancel.setMinimumWidth(80)
        ok = QPushButton('OK')
        ok.setObjectName('primary')
        ok.setMinimumWidth(80)
        ok.setDefault(True)
        btns.addWidget(cancel)
        btns.addWidget(ok)
        outer.addLayout(btns)

        ok.clicked.connect(self._ok)
        cancel.clicked.connect(self._cancel)
        self._entry.returnPressed.connect(self._ok)
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self,
                  activated=self._cancel)
        self._entry.setFocus()

    def _ok(self) -> None:
        self.result = self._entry.text()
        self.accept()

    def _cancel(self) -> None:
        self.result = None
        self.reject()


class _MultilineDialog(QDialog):
    """Paste-mode editor. Used for ``--stdin`` script verbs."""

    def __init__(self, parent: QWidget,
                 title: str = 'Paste script source') -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(760, 500)
        self.result: Optional[str] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(10)

        hint = QLabel(
            'Paste or type the script source below. '
            'Click Deliver when finished.')
        hint.setStyleSheet(f'color: {Palette.TEXT_MUTED};')
        outer.addWidget(hint)

        self._text = QPlainTextEdit()
        self._text.setFont(_f_mono(10))
        self._text.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.NoWrap)
        outer.addWidget(self._text, 1)

        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = QPushButton('Cancel')
        cancel.setMinimumWidth(90)
        ok = QPushButton('Deliver')
        ok.setObjectName('primary')
        ok.setMinimumWidth(90)
        ok.setDefault(True)
        btns.addWidget(cancel)
        btns.addWidget(ok)
        outer.addLayout(btns)

        ok.clicked.connect(self._ok)
        cancel.clicked.connect(self._cancel)
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self,
                  activated=self._cancel)
        self._text.setFocus()

    def _ok(self) -> None:
        self.result = self._text.toPlainText()
        self.accept()

    def _cancel(self) -> None:
        self.result = None
        self.reject()


# ---------------------------------------------------------------------
# Persistent chat session

class _GuiChat:
    """Chat runs continuously in the GUI, independent of the
    command worker.

    Same design as the Tk version: a long-poll thread from startup
    until shutdown, a ``handle(line)`` method for one line typed at
    the Chat tab's input bar, and rendering through the app's
    ``_gui_chat_render`` queue. The CLI is unaffected.
    """

    HELP_TEXT = (
        'in-chat commands:\n'
        '  /me <text>             send an action\n'
        '  /dm <name>             enter DM mode with <name>\n'
        '  /dm <name> <text>      send one DM without entering DM mode\n'
        '  /dm off                leave DM mode (back to broadcast)\n'
        '  /topic                 show the pinned topic\n'
        '  /topic <text>          set the pinned topic\n'
        '  /topic clear           clear the pinned topic\n'
        '  /who                   list operators at the chat prompt\n'
        '  /history [N]           show last N messages\n'
        '  /history --persist [N] read from the on-disk store\n'
        '  /history @<name> [N]   show DMs with <name>\n'
        '  /history @room [N]     show room messages while in DM mode\n'
        '  /file <path>           share a local file with the team\n'
        '  /get <sha256> [<path>] download a shared file\n'
        '  /files                 list shared files in the store\n'
        '  /delete <sha256>       delete a file you uploaded\n'
        '  /clear                 clear the chat pane\n'
        '  /help                  this list\n'
        '\n'
        'DM privacy: a direct message is filtered out of every '
        "other operator's client, but it is written to the audit "
        'chain and to the chat log verbatim. Neither party can '
        'deny having sent it — that is the point of the audit '
        'chain. Do not use /dm for anything you would not want an '
        'admin reading after the fact.'
    )

    def __init__(self, app) -> None:
        self.app = app
        self.client = app.client
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_id = 0
        self._dm_peer: Optional[str] = None
        self._last_topic = ''
        self._last_day: Optional[str] = None

    def start(self) -> None:
        try:
            r = self.client.tp.post(
                '/api/v1/chat/history', {'limit': 200})
            fetched = list(r.get('messages') or [])
            history_topic = r.get('topic') or {}
        except Exception as exc:
            self.app._log(f"chat history unavailable: {exc}", 'warn')
            fetched = []
            history_topic = {}

        topic_text = (history_topic or {}).get('text', '')
        self.app._gui_chat_render_topic(history_topic)
        self._last_topic = topic_text

        for m in fetched:
            mid = m.get('id', 0)
            if mid > self._last_id:
                self._last_id = mid
            ts = m.get('ts')
            if ts is not None:
                self._last_day = _chat_day_label(ts)

        recent = fetched[-15:]
        last_day = None
        for m in recent:
            ts = m.get('ts')
            if ts is not None:
                day = _chat_day_label(ts)
                if day != last_day:
                    self.app._gui_chat_render({
                        'operator': 'system', 'role': '',
                        'kind': 'day', 'text': day, 'ts': ts,
                    })
                    last_day = day
            self.app._gui_chat_render(m)

        self.app._gui_chat_render({
            'operator': 'system', 'role': '',
            'kind': 'system',
            'text': ('chat connected — messages arrive in this tab '
                     'as they come; the Log tab runs beacon '
                     'commands independently'),
            'ts': time.time(),
        })

        try:
            self.client.tp.post(
                '/api/v1/chat/send',
                {'kind': 'notice', 'event': 'join'}, timeout=3.0)
        except Exception:
            pass

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._poller, name='gui-chat-poller', daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=8.0)
            self._thread = None
        try:
            self.client.tp.post(
                '/api/v1/chat/send',
                {'kind': 'notice', 'event': 'leave'}, timeout=3.0)
        except Exception:
            pass

    def _poller(self) -> None:
        errors = 0
        while not self._stop.is_set():
            if not self.app._on_chat_tab():
                if self._stop.wait(2.0):
                    return
                continue
            try:
                r = self.client.tp.post(
                    '/api/v1/chat/poll',
                    {'after': self._last_id, 'wait': 2.0}, timeout=8.0)
                errors = 0
            except Exception:
                errors += 1
                if errors >= 5:
                    self.app._gui_chat_render({
                        'operator': 'system', 'role': '',
                        'kind': 'system',
                        'text': ('chat poll failed repeatedly — '
                                 'chat may be offline'),
                        'ts': time.time(),
                    })
                    return
                if self._stop.wait(2.0):
                    return
                continue

            new_topic = r.get('topic') or {}
            new_text = new_topic.get('text', '')
            if new_text != self._last_topic:
                self._last_topic = new_text
                try:
                    self.app._gui_chat_render_topic(new_topic)
                except Exception:
                    pass

            for m in (r.get('messages') or []):
                mid = m.get('id', 0)
                if mid > self._last_id:
                    self._last_id = mid
                if m.get('operator') == self.client.name:
                    continue
                ts = m.get('ts')
                if ts is not None:
                    day = _chat_day_label(ts)
                    if day != self._last_day:
                        self._last_day = day
                        self.app._gui_chat_render({
                            'operator': 'system', 'role': '',
                            'kind': 'day', 'text': day, 'ts': ts,
                        })
                try:
                    self.app._gui_chat_render(m)
                except Exception:
                    pass

    def handle(self, line: str) -> None:
        if not line.strip():
            return
        if line.startswith('/'):
            try:
                self._handle_slash(line)
            except Exception as exc:
                self.app._log(f"chat command error: {exc}", 'err')
            return
        if self._dm_peer:
            self._send_dm(self._dm_peer, line)
        else:
            self._send_broadcast(line)

    def _send_broadcast(self, text: str) -> None:
        try:
            r = self.client.tp.post(
                '/api/v1/chat/send', {'text': text})
        except Exception as exc:
            self._chat_print(f'send failed: {exc}')
            return
        msg = (r or {}).get('message')
        if not isinstance(msg, dict):
            msg = {
                'operator': self.client.name,
                'role': self.client.role,
                'kind': 'chat',
                'text': text,
                'ts': time.time(),
            }
        self.app._gui_chat_render(msg)

    def _send_dm(self, recipient: str, text: str) -> None:
        try:
            self.client.tp.post(
                '/api/v1/chat/send',
                {'kind': 'dm', 'recipient': recipient,
                 'text': text})
        except Exception as exc:
            self._chat_print(f'dm failed: {exc}')
            return
        self.app._gui_chat_render({
            'operator': self.client.name,
            'role': self.client.role,
            'kind': 'dm',
            'recipient': recipient,
            'text': text,
            'ts': time.time(),
        })

    def _send_action(self, text: str) -> None:
        if self._dm_peer:
            self._send_dm(self._dm_peer, text)
            return
        try:
            self.client.tp.post(
                '/api/v1/chat/send',
                {'kind': 'action', 'text': text})
        except Exception as exc:
            self._chat_print(f'action failed: {exc}')
            return
        self.app._gui_chat_render({
            'operator': self.client.name,
            'role': self.client.role,
            'kind': 'action',
            'text': text,
            'ts': time.time(),
        })

    def _chat_print(self, text: str) -> None:
        self.app._chat_q.put(('raw', text))

    def _handle_slash(self, line: str) -> None:
        head = line[1:].split()
        if not head:
            return
        sub = head[0].lower()

        if sub in ('help', 'h', '?'):
            for ln in self.HELP_TEXT.split('\n'):
                self._chat_print(ln)
        elif sub == 'clear':
            self.app.sig_post.emit(self.app._clear_chat)
        elif sub == 'me':
            if len(head) < 2:
                self._chat_print('usage: /me <text>')
                return
            self._send_action(' '.join(head[1:]))
        elif sub == 'dm':
            self._cmd_dm(head)
        elif sub == 'who':
            self._cmd_who()
        elif sub in ('history', 'hist'):
            self._cmd_history(head)
        elif sub == 'topic':
            self._cmd_topic(head)
        elif sub == 'files':
            self._cmd_files()
        elif sub == 'file':
            self._cmd_file(head)
        elif sub in ('get', 'download'):
            self._cmd_get(head)
        elif sub in ('delete', 'del', 'rm'):
            self._cmd_delete(head)
        else:
            self._chat_print(f'unknown /command: {sub} '
                             f'(try /help)')

    def _cmd_dm(self, head) -> None:
        if len(head) < 2:
            self._chat_print(
                'usage: /dm <name> [<text>]  |  /dm off')
            return
        target = head[1]
        if target.lower() in ('off', 'exit', 'leave', 'none'):
            self._dm_peer = None
            self._chat_print('left DM mode — back to broadcast')
            self.app.sig_post.emit(self.app._update_input_prompt)
            return
        if len(head) >= 3:
            text = ' '.join(head[2:])
            self._send_dm(target, text)
            return
        self._dm_peer = target
        self._chat_print(f'entered DM mode with {target} — '
                         f'/dm off to leave')
        self.app.sig_post.emit(self.app._update_input_prompt)

    def _cmd_who(self) -> None:
        try:
            r = self.client.tp.post('/api/v1/chat/who', {})
            ops = r.get('operators') or []
        except Exception as exc:
            self._chat_print(f'{exc}')
            return
        if not ops:
            self._chat_print('no one at the prompt')
            return
        self._chat_print('at the chat prompt:')
        for o in ops:
            oname = o.get('name', '?')
            orole = o.get('role', '')
            idle = float(o.get('idle_seconds', 0))
            active = bool(o.get('active'))
            state = 'active' if active else f'idle {int(idle)}s'
            you = ' (you)' if oname == self.client.name else ''
            self._chat_print(f'  {oname:<20} @{orole:<10} '
                             f'{state}{you}')

    def _cmd_history(self, head) -> None:
        n = 20
        peer = None
        persistent = False
        for arg in head[1:]:
            low = arg.lower()
            if low in ('--persist', '-p', 'persist', 'persistent'):
                persistent = True
            elif arg.startswith('@'):
                peer = arg[1:]
            else:
                try:
                    n = max(1, min(int(arg), 200))
                except ValueError:
                    pass

        if peer == 'room':
            peer = None
            force_room = True
        else:
            force_room = False

        if (peer is None and not force_room and self._dm_peer):
            peer = self._dm_peer

        body = {'limit': n}
        if peer:
            body['peer'] = peer
        if persistent:
            body['persistent'] = True

        try:
            r = self.client.tp.post('/api/v1/chat/history', body)
            msgs = r.get('messages') or []
        except Exception as exc:
            self._chat_print(f'{exc}')
            return

        if persistent and peer:
            self._chat_print(f'DM history with {peer} (persistent):')
        elif persistent:
            self._chat_print('persistent room history '
                             '(survives restart):')
        elif peer:
            self._chat_print(f'DM history with {peer}:')

        last_day = None
        for m in msgs:
            ts = m.get('ts')
            if ts is not None:
                day = _chat_day_label(ts)
                if day != last_day:
                    self.app._gui_chat_render({
                        'operator': 'system', 'role': '',
                        'kind': 'day', 'text': day, 'ts': ts,
                    })
                    last_day = day
            self.app._gui_chat_render(m)

    def _cmd_topic(self, head) -> None:
        if len(head) < 2:
            try:
                r = self.client.tp.post('/api/v1/chat/topic', {})
                t = r.get('topic') or {}
            except Exception as exc:
                self._chat_print(f'{exc}')
                return
            text = t.get('text', '')
            if not text:
                self._chat_print('(no topic set)')
            else:
                self.app._gui_chat_render_topic(t)
            return
        spec = ' '.join(head[1:]).strip()
        if spec.lower() in ('clear', 'off', 'none'):
            spec = ''
        try:
            self.client.tp.post('/api/v1/chat/topic', {'text': spec})
        except Exception as exc:
            self._chat_print(f'topic set failed: {exc}')
            return
        if spec:
            self._last_topic = spec
            self._chat_print('topic set')
        else:
            self._last_topic = ''
            self._chat_print('topic cleared')

    def _cmd_files(self) -> None:
        try:
            r = self.client.tp.post(
                '/api/v1/chat/files', {}, timeout=10.0)
            rows = r.get('files') or []
        except Exception as exc:
            self._chat_print(f'{exc}')
            return
        if not rows:
            self._chat_print('(no files in the store)')
            return
        self._chat_print(f'FILES  ·  {len(rows)}')
        for f in rows:
            h = f.get('sha256', '')
            nm = f.get('name', '') or '?'
            sz = _human_bytes(int(f.get('size', 0)))
            owner = f.get('owner', '?')
            ts = f.get('ts', 0)
            when = time.strftime(
                '%Y-%m-%d %H:%M', time.localtime(ts)) if ts else '?'
            self._chat_print(f'  {h}')
            self._chat_print(f'    {nm:<32}  {sz:>8}  '
                             f'{owner:<14} {when}')
        self._chat_print('/get <sha256>  to download')

    def _cmd_file(self, head) -> None:
        if len(head) < 2:
            self._chat_print('usage: /file <path>')
            return
        path = ' '.join(head[1:])
        try:
            with open(path, 'rb') as fh:
                data = fh.read()
        except OSError as exc:
            self._chat_print(f'read failed: {exc}')
            return
        if not data:
            self._chat_print('file is empty')
            return
        b64 = _b64.b64encode(data).decode('ascii')
        fname = os.path.basename(path) or 'file'
        try:
            r = self.client.tp.post(
                '/api/v1/chat/file/upload',
                {'name': fname, 'data_b64': b64}, timeout=120.0)
        except Exception as exc:
            self._chat_print(f'upload failed: {exc}')
            return
        if not r.get('ok'):
            self._chat_print(f"{r.get('error', 'upload failed')}")
            return
        m = r.get('message') or {}
        if m:
            self.app._gui_chat_render(m)
        if r.get('deduped'):
            self._chat_print('(identical bytes already in the '
                             'store; deduplicated)')

    def _cmd_get(self, head) -> None:
        if len(head) < 2:
            self._chat_print('usage: /get <sha256> [<path>]')
            return
        digest = head[1].lower().strip()
        out_path = head[2] if len(head) > 2 else digest
        try:
            r = self.client.tp.post(
                '/api/v1/chat/file/download',
                {'sha256': digest}, timeout=120.0)
        except Exception as exc:
            self._chat_print(f'download failed: {exc}')
            return
        if not r.get('ok'):
            self._chat_print(f"{r.get('error', 'not found')}")
            return
        try:
            data = _b64.b64decode(r.get('data_b64') or '')
        except Exception:
            self._chat_print('bad response encoding')
            return
        got = hashlib.sha256(data).hexdigest()
        if got != digest:
            self._chat_print('sha256 mismatch — refusing to write')
            return
        try:
            with open(out_path, 'wb') as fh:
                fh.write(data)
        except OSError as exc:
            self._chat_print(f'write failed: {exc}')
            return
        self._chat_print(f'saved {out_path} '
                         f'({_human_bytes(len(data))})')

    def _cmd_delete(self, head) -> None:
        if len(head) < 2:
            self._chat_print('usage: /delete <sha256>')
            return
        digest = head[1].lower().strip()
        try:
            r = self.client.tp.post(
                '/api/v1/chat/file/delete',
                {'sha256': digest}, timeout=30.0)
        except Exception as exc:
            self._chat_print(f'delete failed: {exc}')
            return
        if not r.get('ok'):
            self._chat_print(f"{r.get('error', 'delete failed')}")
            return
        self._chat_print(f'deleted sha256:{digest[:12]}… '
                         f'({_human_bytes(r.get("size", 0))})')


# ---------------------------------------------------------------------
# Build dialog

class _BuildDialog(QDialog):
    """Dynamic remote-build form.

    Field visibility depends on three selectors (transport, target
    OS, output format). Values live in ``self._v`` — a plain Python
    dict — rather than in the widgets, so a rebuild never loses an
    already-entered value.
    """

    def __init__(self, parent: QWidget, client) -> None:
        super().__init__(parent)
        self.client = client
        self.result: Optional[dict] = None
        self.setWindowTitle('Build agent')
        self.setModal(True)
        self.resize(940, 760)
        self.setMinimumSize(660, 480)

        # ---------- Model: the source of truth ----------
        self._v: dict = {
            'os': 'linux',
            'arch': 'amd64',
            'fmt': 'elf',
            'transport': 'http',
            'url': (f"https://{client.cfg.get('server_host', 'c2')}"
                    f":{getattr(client, 'beacon_port', None) or 8881}"),
            'dns_domain': '',
            'dns_resolver': '',
            'doh_resolver': 'https://cloudflare-dns.com/dns-query',
            'doh_host_header': '',
            'icmp_host': '',
            'smb_pipe': 'tornado_relay_001',
            'smb_relay_pipe': '',
            'tcp_bind_addr': '0.0.0.0:4444',
            'tcp_bind_token': '',
            'tcp_relay_target': '',
            'tcp_relay_token': '',
            'tcp_rev_listen': '',
            'tcp_rev_target': '',
            'tcp_rev_token': '',
            'wg_server_pubkey': '',
            'wg_server_addr': '',
            'wg_agent_privkey': '',
            'wg_tunnel_ip': '10.99.0.2',
            'wg_server_tunnel_ip': '10.99.0.1',
            'wg_inner_port': '8881',
            'failover_after': '3',
            'pivot_key_path': 'mtls_certs/pivot.pem',
            'identity_role': '',
            'opsec_profile': 'stealth',
            'c2_profile': '',
            'tls_profile': 'go',
            'kill_days': '30',
            'wh_spec': '08:00-19:00',
            'stage_name': '',
            'stage_key_hex': '',
            'mtls': False,
            'inject': False,
            'inject_method': 'default',
            'verbose': False,
        }

        # ---------- Layout ----------
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 18, 20, 16)
        outer.setSpacing(10)

        hdr = QLabel('Remote agent build')
        hdr.setObjectName('dlgHeader')
        outer.addWidget(hdr)
        sub = QLabel('The team server compiles the binary and '
                     'streams it back. The fields update as you '
                     'change the transport.')
        sub.setObjectName('dlgSub')
        sub.setWordWrap(True)
        outer.addWidget(sub)

        self.breadcrumb = QLabel('')
        self.breadcrumb.setObjectName('breadcrumb')
        outer.addWidget(self.breadcrumb)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(self._scroll, 1)

        self._form = QWidget()
        self._form.setStyleSheet(f'background: {Palette.BG};')
        self._grid = QGridLayout(self._form)
        self._grid.setContentsMargins(0, 0, 8, 0)
        self._grid.setHorizontalSpacing(16)
        self._grid.setVerticalSpacing(6)
        self._grid.setColumnStretch(1, 1)
        self._scroll.setWidget(self._form)

        self.summary = QLabel('')
        self.summary.setObjectName('summaryStrip')
        self.summary.setWordWrap(True)
        outer.addWidget(self.summary)

        btns = QHBoxLayout()
        load = QPushButton('Load config…')
        load.setObjectName('ghost')
        load.setMinimumWidth(110)
        btns.addWidget(load)
        btns.addStretch(1)
        cancel = QPushButton('Cancel')
        cancel.setMinimumWidth(90)
        build = QPushButton('Build')
        build.setObjectName('primary')
        build.setMinimumWidth(90)
        build.setDefault(True)
        btns.addWidget(cancel)
        btns.addWidget(build)
        outer.addLayout(btns)

        load.clicked.connect(self._load_from_json)
        cancel.clicked.connect(self.reject)
        build.clicked.connect(self._ok)
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self,
                  activated=self.reject)

        self._row_idx = 0
        self._build_form()

    def _static_hint(self, text: str) -> QLabel:
        """A hint line that sits in the value column, not the
        label column, so it reads as prose under the field it
        describes."""
        lbl = QLabel(text)
        lbl.setObjectName('formHint')
        lbl.setWordWrap(True)
        return lbl

    # ------------------------------------------------------------------
    # Widget factories

    _STRUCTURAL_FIELDS = frozenset({
        'smb_relay_pipe', 'tcp_relay_target', 'tcp_rev_listen',
    })

    def _entry(self, key: str, width_chars: int = 44) -> QLineEdit:
        w = QLineEdit()
        w.setFont(_f_ui(10))
        w.setText(str(self._v.get(key, '')))
        w.setMinimumWidth(width_chars * 7)
        w.textChanged.connect(
            lambda txt, k=key: self._v.__setitem__(k, txt))
        w.textChanged.connect(lambda _t: self._update_preview())
        if key in self._STRUCTURAL_FIELDS:
            w.textChanged.connect(
                lambda txt, k=key: self._on_structural_change(k, txt))
        return w

    def _on_structural_change(self, key: str, txt: str) -> None:
        """Rebuild the form when a structural field crosses the
        empty/non-empty boundary. Preserve the field's value and
        cursor position across the rebuild so the operator can
        keep typing without a visible interruption."""
        was_empty = not getattr(self, '_structural_prev', {}).get(key, '')
        now_empty = not txt.strip()
        if was_empty == now_empty:
            return
        if not hasattr(self, '_structural_prev'):
            self._structural_prev = {}
        self._structural_prev[key] = txt
        self._rebuild()

    def _combo(self, key: str, values: list,
               on_change=None) -> QComboBox:
        w = QComboBox()
        w.setFont(_f_ui(10))
        w.addItems(values)
        w.setEditable(False)
        cur = str(self._v.get(key, values[0] if values else ''))
        if cur in values:
            w.setCurrentText(cur)
        w.setMinimumWidth(240)

        def handler(txt: str, k=key) -> None:
            self._v[k] = txt
            if on_change is not None:
                on_change(txt)
            else:
                self._update_preview()
        w.currentTextChanged.connect(handler)
        return w

    def _check(self, key: str, label: str,
               on_change=None) -> QCheckBox:
        w = QCheckBox(label)
        w.setFont(_f_ui(10))
        w.setChecked(bool(self._v.get(key, False)))

        def handler(b: bool, k: str = key) -> None:
            self._v[k] = b
            if on_change is not None:
                on_change(b)
            else:
                self._update_preview()

        w.toggled.connect(handler)
        return w

    # ------------------------------------------------------------------
    # Layout helpers for the grid

    def _heading(self, step: str, text: str) -> None:
        """Render a numbered section heading.

        `step` is a marker like '1/5' or '2a'. The handler wizard
        uses the same `[N/M]` convention; the GUI keeps the shape
        so an operator who has used one recognises the other."""
        label = f"[{step}]  {text}" if step else text
        lbl = QLabel(label)
        lbl.setObjectName('formHeading')
        self._grid.addWidget(lbl, self._row_idx, 0, 1, 2)
        self._row_idx += 1

    def _hint(self, text: str) -> None:
        """Render a hint line under the field above it.

        Hint text lives in the value column, not the label
        column, so it reads as prose under the field rather
        than as another label."""
        lbl = QLabel(text)
        lbl.setObjectName('formHint')
        lbl.setWordWrap(True)
        self._grid.addWidget(lbl, self._row_idx, 1)
        self._row_idx += 1

    def _row(self, label: str, widget: QWidget) -> None:
        lbl = QLabel(label)
        lbl.setObjectName('formLabel')
        lbl.setAlignment(Qt.AlignmentFlag.AlignRight
                         | Qt.AlignmentFlag.AlignTop)
        self._grid.addWidget(lbl, self._row_idx, 0)
        self._grid.addWidget(widget, self._row_idx, 1)
        self._row_idx += 1

    def _update_preview(self) -> None:
        """Refresh the breadcrumb and summary strips from
        ``self._v``. Called on form rebuild and on every text
        change in a field, so both stay live as the operator
        types."""
        v = self._v
        modes = v['transport'].split(',')

        crumb = ' · '.join((
            v['os'], v['arch'], v['fmt'], v['transport'],
        ))
        self.breadcrumb.setText(f"  {crumb}")

        endpoint = ''
        if 'http' in modes or 'quic' in modes \
                or 'websocket' in modes:
            endpoint = v.get('url', '') or '(no URL)'
        elif 'dns' in modes or 'doh' in modes:
            zone = v.get('dns_domain', '') or '(no zone)'
            endpoint = f"dns://{zone}"
        elif 'icmp' in modes:
            endpoint = v.get('icmp_host', '') or '(no host)'
        elif 'wireguard' in modes:
            endpoint = v.get('wg_server_addr', '') or '(no addr)'
        elif 'smb' in modes:
            endpoint = f"pipe:{v.get('smb_pipe', '') or '?'}"
        elif 'tcp' in modes:
            endpoint = f"listen:{v.get('tcp_bind_addr', '') or '?'}"
        elif 'tcprev' in modes:
            endpoint = f"dial:{v.get('tcp_rev_target', '') or '?'}"

        is_pivot = ('smb' in modes or 'tcp' in modes
                    or 'tcprev' in modes
                    or bool(v.get('smb_relay_pipe'))
                    or bool(v.get('tcp_relay_target'))
                    or bool(v.get('tcp_rev_listen')))

        tail_parts = [v['opsec_profile']]
        kd = (v.get('kill_days') or '').strip()
        if kd and kd != '0':
            tail_parts.append(f"kill {kd}d")
        if is_pivot:
            pk = v.get('pivot_key_path', '').strip()
            tail_parts.append(
                f"pivot key: {pk}" if pk else 'pivot key: MISSING')
        if v.get('mtls'):
            tail_parts.append('mTLS')
        if v.get('inject') and v['fmt'] != 'stager':
            method = v.get('inject_method', 'default')
            if method == 'apc':
                tail_parts.append('inject:apc')
            else:
                tail_parts.append('inject')
        tail = '  ·  '.join(tail_parts)

        line = f"  {crumb}"
        if endpoint:
            line += f"  →  {endpoint}"
        line += f"  ·  {tail}"
        self.summary.setText(line)

    # ------------------------------------------------------------------
    # Transport catalogue
    #
    # Each entry maps a `transport_mode` value to a display label.
    # Adding a new transport to the wizard is one entry here plus
    # one conditional block below for any transport-specific
    # options. The framework-side work to add a transport is
    # documented in README.md › Extending TornadoC2 › Adding a
    # transport — two classes plus mechanical glue across seven
    # files. The wizard itself only needs the display label and
    # the transport_mode value; it does not touch the transport
    # implementation.

    @staticmethod
    def _transport_options(target_os: str):
        opts = [
            ('http',      'http  —  HTTPS + JSON'),
            ('quic',      'quic  —  HTTP/3 over UDP'),
            ('websocket', 'websocket  —  wss:// single-shot'),
            ('dns',       'dns  —  UDP DNS TXT'),
            ('doh',       'doh  —  DNS over HTTPS'),
            ('wireguard', 'wireguard  —  UDP tunnel'),
            ('http,dns',  'http + dns  (failover)'),
            ('http,doh',  'http + doh  (failover)'),
            ('dns,doh',   'dns + doh  (failover)'),
        ]
        if target_os == 'windows':
            opts.append(('smb',
                         'smb  —  named-pipe pivot (Windows)'))
        if target_os == 'linux':
            opts.append(('icmp', 'icmp  —  echo (Linux only)'))
        opts.append(('tcp', 'tcp  —  TCP-bind pivot'))
        opts.append(('tcprev', 'tcprev  —  TCP-reverse pivot'))
        return opts

    # ------------------------------------------------------------------
    # Form rebuild

    def _build_form(self) -> None:
        # Clear
        while self._grid.count():
            item = self._grid.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        self._row_idx = 0

        modes = self._v['transport'].split(',')
        target_os = self._v['os']
        fmt = self._v['fmt']

        # ---------- [1/5] TARGET ----------
        self._heading('1/5', 'TARGET')
        self._row('Target OS',
                  self._combo('os', ['linux', 'windows'],
                              on_change=self._on_os_change))
        arch_values = ['amd64', 'arm64']
        if target_os == 'windows':
            arch_values.append('386')
        if self._v['arch'] not in arch_values:
            self._v['arch'] = arch_values[0]
        self._row('Architecture',
                  self._combo('arch', arch_values))

        fmt_values = (['exe', 'dll', 'shellcode', 'stager']
                      if target_os == 'windows'
                      else ['elf', 'shellcode', 'stager'])
        if self._v['fmt'] not in fmt_values:
            self._v['fmt'] = fmt_values[0]
            fmt = fmt_values[0]
        self._row('Output format',
                  self._combo('fmt', fmt_values,
                              on_change=lambda _t: self._rebuild()))

        # ---------- [1a] STAGER ----------
        if fmt == 'stager':
            self._heading('1a', 'STAGER')
            self._hint('The stager is a minimal first-stage '
                       'implant. It checks in, fetches the full '
                       'agent from the server, verifies its '
                       'ECDSA signature and SHA-256, decrypts it '
                       'in memory, and executes it. The full '
                       'agent must already be staged under '
                       'payloads/ on the server.')
            self._row('Stage name (payload stem)',
                      self._entry('stage_name', 32))
            self._hint('Required. The payload stem the server '
                       'serves — "full" for payloads/full.bin. '
                       'The AES key is recorded against this '
                       'name in payloads/stage_keys.json so the '
                       'server can find it.')
            self._row('Stage key hex (blank = auto)',
                      self._entry('stage_key_hex', 44))
            self._hint('Optional. A 32-byte AES-256-GCM key, '
                       'hex-encoded. Leave blank to have the '
                       'server generate a fresh key per build.')

        # ---------- [2/5] TRANSPORT ----------
        self._heading('2/5', 'TRANSPORT')
        opts = self._transport_options(target_os)
        value_by_label = {lab: v for v, lab in opts}
        label_by_value = {v: lab for v, lab in opts}

        tp = QComboBox()
        tp.setFont(_f_ui(10))
        tp.addItems([lab for _v, lab in opts])
        tp.setEditable(False)
        cur_val = self._v['transport']
        tp.setCurrentText(label_by_value.get(cur_val,
                                             opts[0][1]))
        tp.setMinimumWidth(320)

        def on_tp(_txt):
            lab = tp.currentText()
            val = value_by_label.get(lab, lab)
            if val != self._v['transport']:
                self._v['transport'] = val
                self._rebuild()

        tp.currentTextChanged.connect(on_tp)
        self._row('Transport', tp)
        self._hint('Single-transport builds (quic, websocket, '
                   'smb, tcp, wireguard, icmp) cannot be '
                   'combined with another transport in this '
                   'version. Only http, dns, and doh may be '
                   'combined into a failover list.')

        # ---------- [2a] TRANSPORT OPTIONS ----------
        opt_rows = []

        if 'smb' in modes:
            opt_rows.append(('SMB pipe name or UNC path (child-side)',
                             self._entry('smb_pipe', 32)))
            opt_rows.append(('', self._static_hint(
                'Bare name (tornado_relay_001) → same-host pivot; '
                'the child opens a local pipe on its own machine. '
                'UNC path (\\\\WIN-SRV2\\pipe\\tornado_relay_001) '
                '→ cross-host pivot; the child opens a pipe on '
                'WIN-SRV2 over SMB. WIN-SRV2 must be resolvable '
                'from the child and reachable on TCP/445. On bash, '
                'single-quote the UNC form so the shell does not '
                'collapse the leading backslashes.')))

        if 'wireguard' in modes:
            opt_rows.append(('Server WireGuard public key (base64)',
                             self._entry('wg_server_pubkey', 44)))
            opt_rows.append(('Server UDP address (host:port)',
                             self._entry('wg_server_addr', 32)))
            opt_rows.append(('Agent WireGuard private key (base64)',
                             self._entry('wg_agent_privkey', 44)))
            opt_rows.append(('Agent tunnel IPv4',
                             self._entry('wg_tunnel_ip', 20)))
            opt_rows.append(
                ('Server tunnel IPv4 (matches --wireguard-server-ip)',
                 self._entry('wg_server_tunnel_ip', 20)))
            opt_rows.append(('Inner HTTPS port (matches --beacon-port)',
                             self._entry('wg_inner_port', 10)))

        if 'tcp' in modes:
            opt_rows.append(('TCP bind address (child-side)',
                             self._entry('tcp_bind_addr', 32)))
            opt_rows.append(
                ('TCP bind token (64 hex, from the parent build)',
                 self._entry('tcp_bind_token', 44)))
            opt_rows.append(('', self._static_hint(
                'Shared secret between the child and the parent. '
                'Generate it on the parent side — build the parent '
                'first, click Generate there, and paste the value '
                'into this field. The two must match exactly.')))

        if 'tcprev' in modes:
            opt_rows.append(('TCP reverse target (parent host:port)',
                             self._entry('tcp_rev_target', 32)))
            opt_rows.append(
                ('TCP reverse token (64 hex, from the parent build)',
                 self._entry('tcp_rev_token', 44)))
            opt_rows.append(('', self._static_hint(
                'The child dials out to the parent. Reverse of '
                'tcp-bind: the parent listens, the child connects. '
                'Generate the token on the parent side — build the '
                'parent first, click Generate there, and paste the '
                'value into this field. The two must match exactly.')))

        is_child = ('smb' in modes or 'tcp' in modes
                    or 'tcprev' in modes)

        if not is_child and target_os == 'windows':
            opt_rows.append(('SMB relay pipe (parent-side, blank = skip)',
                             self._entry('smb_relay_pipe', 32)))
        if not is_child:
            opt_rows.append(('TCP relay target (parent-side, blank = skip)',
                             self._entry('tcp_relay_target', 32)))
            relay_tok_wrap = QWidget()
            relay_tok_l = QHBoxLayout(relay_tok_wrap)
            relay_tok_l.setContentsMargins(0, 0, 0, 0)
            relay_tok_l.setSpacing(6)
            relay_tok_l.addWidget(
                self._entry('tcp_relay_token', 44), 1)
            relay_gen = QPushButton('Generate')
            relay_gen.setObjectName('ghost')
            relay_gen.clicked.connect(self._gen_tcp_relay_token)
            relay_tok_l.addWidget(relay_gen)
            opt_rows.append(
                ('TCP relay token (parent-side, if target set)',
                 relay_tok_wrap))

            opt_rows.append(
                ('TCP reverse listen (parent-side, blank = skip)',
                 self._entry('tcp_rev_listen', 32)))
            rev_tok_wrap = QWidget()
            rev_tok_l = QHBoxLayout(rev_tok_wrap)
            rev_tok_l.setContentsMargins(0, 0, 0, 0)
            rev_tok_l.setSpacing(6)
            rev_tok_l.addWidget(
                self._entry('tcp_rev_token', 44), 1)
            rev_gen = QPushButton('Generate')
            rev_gen.setObjectName('ghost')
            rev_gen.clicked.connect(self._gen_tcp_rev_token)
            rev_tok_l.addWidget(rev_gen)
            opt_rows.append(
                ('TCP reverse token (parent-side, if listen set)',
                 rev_tok_wrap))

        if len(modes) > 1:
            opt_rows.append(('Failover after N failures',
                             self._entry('failover_after', 8)))

        if opt_rows:
            self._heading('2a', 'TRANSPORT OPTIONS')
            if 'wireguard' in modes:
                self._hint('The handler prints its WireGuard '
                           'public key at startup. Generate an '
                           'agent keypair out of band with '
                           '`wg genkey | tee agent.key | wg '
                           'pubkey`; paste the private half '
                           'here and pin the public half on the '
                           'server after deployment with '
                           '`wireguard add-peer`.')
            elif 'tcp' in modes:
                self._hint('The beacon opens a TCP listener and '
                           'waits for a parent to dial in. '
                           'Generate a token and pass the same '
                           'value to the parent\'s '
                           '--tcp-relay-token.')
            for label, w in opt_rows:
                self._row(label, w)

        # ---------- [3/5] PIVOT ----------
        is_pivot = ('smb' in modes or 'tcp' in modes
                    or 'tcprev' in modes
                    or self._v.get('smb_relay_pipe')
                    or self._v.get('tcp_relay_target')
                    or self._v.get('tcp_rev_listen'))
        if is_pivot:
            self._heading('3/5', 'PIVOT')
            self._hint('Every SMB and TCP build — parent or '
                       'child — reads the same engagement-wide '
                       'ECDSA P-256 keypair from '
                       'mtls_certs/pivot.pem on the team '
                       'server. The path is fixed for remote '
                       'builds; the local console on the '
                       'server host can override it, but this '
                       'client cannot. Ask your team server '
                       'admin to run `beacon-build '
                       '--pivot-key-gen` if no keypair exists '
                       'yet.')
        else:
            self._heading('3/5', 'PIVOT  ·  not used by this build')
            self._hint('Set a relay pipe or select the smb / tcp '
                       'transport and this section becomes '
                       'active. The path is fixed at '
                       'mtls_certs/pivot.pem on the team '
                       'server.')
        key_entry = self._entry('pivot_key_path', 44)
        key_entry.setReadOnly(True)
        if is_pivot:
            key_entry.setStyleSheet(
                f'color: {Palette.TEXT_MUTED}; '
                f'background: {Palette.BG_SOFT};')
        else:
            key_entry.setEnabled(False)
            key_entry.setStyleSheet(
                f'color: {Palette.TEXT_FAINT}; '
                f'background: {Palette.BG_SOFT};')
        self._row('Pivot keypair (fixed)', key_entry)

        # ---------- [3a] IDENTITY ----------
        self._heading('3a', 'IDENTITY')
        self._hint(
            'Optional disambiguator, mixed into the server\'s '
            'session fingerprint. Two agents built from the same '
            'tree that run on the same host under the same user '
            'report identical (machine_id, hostname, username, os) '
            'tuples and would resolve to one session — one cookie, '
            'one task queue, one row in the beacon list. The '
            'builder already defaults the role for the three pivot '
            'child transports (smb-child, tcp-bind, tcp-rev); '
            'leave this blank to accept that default. Set an '
            'explicit value only when a pivot child needs a name '
            'other than the transport default, or when two '
            'non-pivot builds will run side by side on the same '
            'host under the same user. The role travels in its own '
            'wire field — the beacon list still shows the '
            'machine\'s real hostname.')
        self._row('Identity role (blank = transport default)',
                  self._entry('identity_role', 32))

        # ---------- [2b] ENDPOINT ----------
        end_rows = []
        if ('http' in modes or 'quic' in modes
                or 'websocket' in modes):
            end_rows.append(('Callback URL',
                             self._entry('url', 44)))
        if 'dns' in modes or 'doh' in modes:
            end_rows.append(('Authoritative zone',
                             self._entry('dns_domain', 44)))
        if 'dns' in modes:
            end_rows.append(
                ('UDP resolver host:port (blank = system)',
                 self._entry('dns_resolver', 32)))
        if 'doh' in modes:
            end_rows.append(('DoH endpoint URL',
                             self._entry('doh_resolver', 44)))
            end_rows.append(('DoH Host header (blank = none)',
                             self._entry('doh_host_header', 32)))
        if 'icmp' in modes:
            end_rows.append(('C2 IPv4 address',
                             self._entry('icmp_host', 20)))

        if end_rows:
            self._heading('2b', 'ENDPOINT')
            if 'quic' in modes:
                self._hint('The URL port must match the '
                           'handler\'s --beacon-quic-port. The '
                           'tls_profile field is accepted but '
                           'ignored on a QUIC build.')
            elif 'websocket' in modes:
                self._hint('The URL port must match the '
                           'handler\'s --ws-port, not its '
                           '--beacon-port. The client converts '
                           'the https:// scheme to wss:// at '
                           'dial time.')
            elif 'http' in modes:
                self._hint('Use the handler\'s reachable '
                           'address, not 127.0.0.1 unless the '
                           'target is local.')
            for label, w in end_rows:
                self._row(label, w)

        # ---------- [4/5] OPSEC ----------
        self._heading('4/5', 'OPSEC')
        self._row('OPSEC profile',
                  self._combo('opsec_profile',
                              ['default', 'stealth',
                               'opsec', 'paranoid']))
        self._hint('default: no evasion. stealth: string '
                   'obfuscation. opsec: full suite — needs '
                   'garble on the server. paranoid: opsec plus '
                   'UPX and the ekko sleep mask.')
        if any(t in modes for t in
               ('http', 'quic', 'websocket', 'dns', 'doh',
                'smb', 'tcp', 'tcprev')):
            self._row('C2 profile (blank = handler default)',
                      self._entry('c2_profile', 32))
            if 'dns' in modes or 'doh' in modes:
                self._hint('On a DNS or DoH build the profile '
                           'supplies only the dns_label block — '
                           'the three verb characters and the '
                           'per-chunk payload length. Pick '
                           '"dns" unless the listener is '
                           'dispatching against a different '
                           'profile, in which case pick the '
                           'same one. The listener and the '
                           'agent must agree on the verb set, '
                           'or every query is refused with an '
                           'unknown-verb error.')
            else:
                self._hint('Controls the HTTP fingerprint — '
                           'User-Agent, request paths, extra '
                           'headers — and the malleable shaping '
                           'block. Pair it with a matching TLS '
                           'fingerprint: a profile that claims '
                           'Chrome while the ClientHello is the '
                           'Go standard library is a two-signal '
                           'mismatch.')
        if ('http' in modes or 'doh' in modes
                or 'websocket' in modes):
            self._row('TLS fingerprint',
                      self._combo('tls_profile',
                                  ['go', 'chrome', 'firefox',
                                   'safari']))
            self._hint('Applied on HTTP, DoH, and WebSocket. '
                       'Accepted but ignored on QUIC and '
                       'WireGuard.')

        # ---------- [5/5] LIFECYCLE ----------
        self._heading('5/5', 'LIFECYCLE')
        self._row('Kill days (0 = no deadline)',
                  self._entry('kill_days', 12))
        self._row('Work hours (HH:MM-HH:MM or off)',
                  self._entry('wh_spec', 20))
        self._hint('Target-local time. Set both bounds equal, '
                   'or use "off", to poll 24/7. A wrapped window '
                   'like 22:00-06:00 polls only overnight.')

        # ---------- [5a] OPTIONS ----------
        self._heading('5a', 'OPTIONS')
        toggles = QWidget()
        tl = QHBoxLayout(toggles)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.setSpacing(18)
        tl.addWidget(self._check('mtls', 'Embed mTLS bundle'))
        if fmt != 'stager':
            tl.addWidget(self._check(
                'inject', 'In-memory injection (+~13 MB)',
                on_change=lambda _b: self._rebuild()))
        tl.addWidget(self._check(
            'verbose', 'Verbose stderr (debug)'))
        tl.addStretch(1)
        self._row('', toggles)

        # ---------- [5b] INJECTION METHOD ----------
        # Shown only when the checkbox above is on and the build
        # is a Windows target — apc is refused on any other OS by
        # the server-side validator, and the CLI's local validator
        # refuses it too. The selector is hidden on Linux rather
        # than disabled, so an operator who is not building for
        # Windows never sees a control they cannot use.
        if (self._v.get('inject') and fmt != 'stager'
                and target_os == 'windows'):
            self._heading('5b', 'INJECTION METHOD')
            self._hint(
                '`migrate <pid>` has two backends on Windows. '
                'default is CreateRemoteThread — the historical '
                'path, highest fidelity, highest signal. apc '
                'queues the shellcode to the target\'s existing '
                'threads through NtQueueApcThread; no new thread, '
                'no remote-thread-creation event, but '
                'NtQueueApcThread is itself instrumented by every '
                'major EDR vendor. The technique is a signal '
                'change, not a signal removal. The operator can '
                'override this at runtime with `migrate <pid> '
                '--method <name>`; the build-time default is '
                'what takes effect when the flag is omitted.')
            self._row(
                'Default method',
                self._combo('inject_method', ['default', 'apc']))
            self._hint(
                'apc requires the injection pass to embed '
                'shellcode — that is the checkbox above. The '
                'build refuses the combination if inject is off, '
                'and refuses apc on any non-Windows target.')

        self._scroll.verticalScrollBar().setValue(0)
        self._update_preview()

    def _on_os_change(self, new_os: str) -> None:
        valid = {v for v, _l in self._transport_options(new_os)}
        modes = self._v['transport'].split(',')
        if not all(m in valid for m in modes):
            self._v['transport'] = 'http'

        if new_os != 'windows':
            self._v['smb_relay_pipe'] = ''
            self._v['smb_pipe'] = ''
        if new_os != 'linux':
            self._v['icmp_host'] = ''
        self._rebuild()

    def _rebuild(self) -> None:
        self._build_form()

    def _gen_tcp_relay_token(self) -> None:
        self._v['tcp_relay_token'] = _secrets.token_hex(32)
        self._rebuild()

    def _gen_tcp_rev_token(self) -> None:
        self._v['tcp_rev_token'] = _secrets.token_hex(32)
        self._rebuild()

    # ------------------------------------------------------------------
    # Load from JSON

    def _load_from_json(self) -> None:
        """Populate the form from a JSON build config.

        The file schema is the same one `beacon-build -c` reads on
        the CLI and the same one `beacon-handler._load_build_config`
        accepts on the server side. This method only maps JSON keys
        onto the widget model; it does not validate — the builder
        on the server remains the source of truth, and any field
        the JSON sets to something the server rejects produces the
        same error the CLI would.

        The picker is delegated to the main window so both JSON
        entry points share the same starting directory and the
        same session-level last-used cache.
        """
        parent = self.parent()
        if parent is not None and hasattr(parent, 'pick_json_config'):
            path = parent.pick_json_config('Load build config')
        else:
            from PySide6.QtWidgets import QFileDialog
            path, _ = QFileDialog.getOpenFileName(
                self, 'Load build config',
                os.getcwd(),
                'JSON config (*.json);;All files (*)')
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(
                self, 'Load failed',
                f'Could not read {path}:\n\n{exc}')
            return
        if not isinstance(data, dict):
            QMessageBox.critical(
                self, 'Load failed',
                'The top-level JSON must be an object.')
            return

        self._apply_json(data)
        self._rebuild()
        QMessageBox.information(
            self, 'Loaded',
            f'Populated the form from '
            f'{os.path.basename(path)}.\n\n'
            f'Review the fields and click Build.')

    def _apply_json(self, data: dict) -> None:
        """Map the JSON schema onto the widget model.

        Most keys share a name; a handful differ (`target_os` vs
        `os`, `transport_mode` vs `transport`, the four WireGuard
        fields, `transport_failover_after` vs `failover_after`).
        `work_hours_start` and `work_hours_end` are recombined
        into the single `wh_spec` field the form uses, and the
        JSON `mtls` object collapses to the boolean the checkbox
        carries.

        A missing or null key is left untouched, so a partial
        config only overwrites the fields it names.
        """
        v = self._v

        def take(json_key: str, v_key: str, cast=None) -> None:
            if json_key not in data:
                return
            val = data[json_key]
            if val is None or val == '':
                return
            if cast is not None:
                try:
                    val = cast(val)
                except (TypeError, ValueError):
                    return
            v[v_key] = val

        take('target_os',              'os')
        take('target_arch',            'arch')
        take('output_format',          'fmt')
        take('transport_mode',         'transport')
        take('url',                    'url')
        take('dns_domain',             'dns_domain')
        take('dns_resolver',           'dns_resolver')
        take('doh_resolver',           'doh_resolver')
        take('doh_host_header',        'doh_host_header')
        take('icmp_host',              'icmp_host')
        take('smb_pipe',               'smb_pipe')
        take('smb_relay_pipe',         'smb_relay_pipe')
        take('tcp_bind_addr',          'tcp_bind_addr')
        take('tcp_bind_token',         'tcp_bind_token')
        take('tcp_relay_target',       'tcp_relay_target')
        take('tcp_relay_token',        'tcp_relay_token')
        take('tcp_rev_listen',         'tcp_rev_listen')
        take('tcp_rev_target',         'tcp_rev_target')
        take('tcp_rev_token',          'tcp_rev_token')
        take('wireguard_server_pubkey',    'wg_server_pubkey')
        take('wireguard_server_addr',      'wg_server_addr')
        take('wireguard_agent_privkey',    'wg_agent_privkey')
        take('wireguard_tunnel_ip',        'wg_tunnel_ip')
        take('wireguard_server_tunnel_ip', 'wg_server_tunnel_ip')
        take('wireguard_inner_port',       'wg_inner_port')
        take('transport_failover_after', 'failover_after',
             cast=lambda x: str(int(x)))
        take('pivot_key_path',         'pivot_key_path')
        take('identity_role',          'identity_role')
        take('opsec_profile',          'opsec_profile')
        take('c2_profile',             'c2_profile')
        take('tls_profile',            'tls_profile')
        take('kill_days',              'kill_days',
             cast=lambda x: str(int(x)))
        take('stage_name',             'stage_name')
        take('stage_key_hex',          'stage_key_hex')
        take('inject',                 'inject', cast=bool)
        take('inject_method',          'inject_method')
        take('verbose',                'verbose', cast=bool)

        mtls = data.get('mtls')
        if isinstance(mtls, dict):
            v['mtls'] = bool(mtls.get('enabled'))
        elif isinstance(mtls, bool):
            v['mtls'] = mtls

        wh_start = data.get('work_hours_start')
        wh_end = data.get('work_hours_end')
        if wh_start and wh_end:
            v['wh_spec'] = f'{wh_start}-{wh_end}'

    # ------------------------------------------------------------------
    # Payload assembly

    def _ok(self) -> None:
        v = self._v
        modes = v['transport'].split(',')
        p: dict = {
            'target_os':      v['os'],
            'target_arch':    v['arch'],
            'output_format':  v['fmt'],
            'transport_mode': v['transport'],
            'opsec_profile':  v['opsec_profile'],
        }

        if ('http' in modes or 'quic' in modes
                or 'websocket' in modes):
            p['url'] = v['url'].strip()

        if any(t in modes for t in ('http', 'websocket', 'doh')):
            p['tls_profile'] = v['tls_profile']

        if 'wireguard' in modes:
            p['wireguard_server_pubkey'] = v['wg_server_pubkey'].strip()
            p['wireguard_server_addr'] = v['wg_server_addr'].strip()
            p['wireguard_agent_privkey'] = v['wg_agent_privkey'].strip()
            p['wireguard_tunnel_ip'] = v['wg_tunnel_ip'].strip()
            srv_tun = v['wg_server_tunnel_ip'].strip()
            if srv_tun:
                p['wireguard_server_tunnel_ip'] = srv_tun
            inner = v['wg_inner_port'].strip()
            if inner:
                p['wireguard_inner_port'] = inner

        if 'dns' in modes or 'doh' in modes:
            p['dns_domain'] = v['dns_domain'].strip()
        if 'dns' in modes and v['dns_resolver'].strip():
            p['dns_resolver'] = v['dns_resolver'].strip()
        if 'doh' in modes:
            if v['doh_resolver'].strip():
                p['doh_resolver'] = v['doh_resolver'].strip()
            if v['doh_host_header'].strip():
                p['doh_host_header'] = v['doh_host_header'].strip()
        if 'icmp' in modes and v['icmp_host'].strip():
            p['icmp_host'] = v['icmp_host'].strip()

        profile_aware = any(t in modes for t in
                            ('http', 'quic', 'websocket',
                             'dns', 'doh', 'smb', 'tcp', 'tcprev'))
        if profile_aware and v['c2_profile'].strip():
            p['c2_profile'] = v['c2_profile'].strip()

        if v['kill_days'].strip().isdigit():
            p['kill_days'] = int(v['kill_days'].strip())
        wh = v['wh_spec'].strip()
        if wh.lower() in ('off', '00:00-00:00'):
            p['work_hours_start'] = '00:00'
            p['work_hours_end'] = '00:00'
        elif '-' in wh:
            a, b = wh.split('-', 1)
            p['work_hours_start'] = a.strip()
            p['work_hours_end'] = b.strip()

        if len(modes) > 1:
            try:
                n = int(v['failover_after'].strip())
                if n >= 0:
                    p['transport_failover_after'] = n
            except (ValueError, AttributeError):
                pass

        if 'smb' in modes and v['smb_pipe'].strip():
            p['smb_pipe'] = v['smb_pipe'].strip()
        if 'tcp' in modes:
            if v['tcp_bind_addr'].strip():
                p['tcp_bind_addr'] = v['tcp_bind_addr'].strip()
            if v['tcp_bind_token'].strip():
                p['tcp_bind_token'] = v['tcp_bind_token'].strip()
        if 'tcprev' in modes:
            if v['tcp_rev_target'].strip():
                p['tcp_rev_target'] = v['tcp_rev_target'].strip()
            if v['tcp_rev_token'].strip():
                p['tcp_rev_token'] = v['tcp_rev_token'].strip()

        if v.get('os') == 'windows' and v['smb_relay_pipe'].strip():
            p['smb_relay_pipe'] = v['smb_relay_pipe'].strip()
        if v['tcp_relay_target'].strip():
            p['tcp_relay_target'] = v['tcp_relay_target'].strip()
        if v['tcp_relay_token'].strip():
            p['tcp_relay_token'] = v['tcp_relay_token'].strip()
        if v['tcp_rev_listen'].strip():
            p['tcp_rev_listen'] = v['tcp_rev_listen'].strip()
            if v['tcp_rev_token'].strip():
                p['tcp_rev_token'] = v['tcp_rev_token'].strip()

        is_pivot = ('smb' in modes or 'tcp' in modes
                    or 'tcprev' in modes
                    or p.get('smb_relay_pipe')
                    or p.get('tcp_relay_target')
                    or p.get('tcp_rev_listen'))
        if is_pivot and v['pivot_key_path'].strip():
            p['pivot_key_path'] = v['pivot_key_path'].strip()

        if v.get('identity_role', '').strip():
            p['identity_role'] = v['identity_role'].strip()

        if v['fmt'] == 'stager':
            if v['stage_name'].strip():
                p['stage_name'] = v['stage_name'].strip()
            if v['stage_key_hex'].strip():
                p['stage_key_hex'] = v['stage_key_hex'].strip()

        if v['mtls']:
            p['mtls'] = {'enabled': True}
        if v['inject'] and v['fmt'] != 'stager':
            p['inject'] = True
            method = (v.get('inject_method') or 'default').strip()
            if method:
                p['inject_method'] = method
        if v['verbose']:
            p['verbose'] = True

        self.result = p
        self.accept()


# ---------------------------------------------------------------------
# Main application

class GuiApp(QMainWindow):
    """Main GUI application. Same Client, same dispatch table."""

    REFRESH_MS = 4000

    # ── Cross-thread signals ────────────────────────────────────
    sig_log             = Signal(str, str)   # line, tag
    sig_chat_msg        = Signal(object)
    sig_chat_topic      = Signal(object)
    sig_chat_raw        = Signal(str)
    sig_beacons         = Signal(object)     # list of rows
    sig_busy            = Signal(bool)
    sig_status          = Signal(str)
    sig_connection      = Signal(str, str)   # host, role
    sig_disconnected    = Signal()
    sig_quit            = Signal()
    sig_force_quit      = Signal()
    sig_post            = Signal(object)     # generic main-thread dispatch

    # ------------------------------------------------------------------

    def __init__(self, cfg, tp, debug: bool = False,
                 config_path: Optional[str] = None) -> None:
        super().__init__()

        self.cfg = cfg
        self.tp = tp
        self.debug = debug
        self.config_path = config_path

        # 1. stdout/stderr swap BEFORE repl import
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr
        self._stdout_q: queue.Queue = queue.Queue()
        self._gui_stream = _GuiStream(self._stdout_q)
        sys.stdout = self._gui_stream
        sys.stderr = self._gui_stream

        # 2. Import repl with the GUI stream in place
        from tornado_client import repl as _repl
        self._repl = _repl
        _repl._COLOR = False
        for k in list(_repl.CLR.keys()):
            _repl.CLR[k] = ''

        # 3. Client
        self.client = _repl.Client(cfg, tp,
                                   config_path=config_path)

        # 4. Chat / thread plumbing
        self._chat_q: queue.Queue = queue.Queue()
        self._chat: Optional[_GuiChat] = None
        self._command_q: queue.Queue = queue.Queue()
        self._input_q: queue.Queue = queue.Queue()
        self._chat_send_q: queue.Queue = queue.Queue()

        self._busy = False
        self._connected = False
        self._shutdown = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._chat_worker: Optional[threading.Thread] = None
        self._init_started = False

        # Tree state
        self._sort_col = 'id'
        self._sort_reverse = False
        self._beacon_rows: list = []
        self._filter_text = ''

        # Cross-thread cache of the active-tab state. The chat
        # poller runs on a plain `threading.Thread` and must not
        # read `self.tabs.currentIndex()` — Qt widgets are not
        # thread-safe. `_on_tab_change` writes this on the main
        # thread; the poller reads it.
        self._chat_tab_active = False

        # Chat grouping state
        self._chat_last_who: Optional[str] = None
        self._chat_last_ts: float = 0

        # Input history
        self._history: list[str] = []

        # Session-level cache of the last directory a JSON build
        # config was loaded from. Used to default both the File
        # menu picker and the in-dialog "Load config…" picker to
        # wherever the operator last found a file.
        self._last_build_dir: Optional[str] = None

        # 5. Window setup
        self.setWindowTitle(
            f"TornadoC2 — {cfg.get('name', '?')} @ "
            f"{cfg.get('server_host', '?')}:"
            f"{cfg.get('server_port', '?')}")
        self.resize(1280, 800)
        self.setMinimumSize(1000, 620)

        # 6. Signals → slots (all delivered on the main thread)
        self.sig_log.connect(self._on_log)
        self.sig_chat_msg.connect(self._append_chat_msg)
        self.sig_chat_topic.connect(self._update_chat_topic)
        self.sig_chat_raw.connect(self._append_chat_raw)
        self.sig_beacons.connect(self._apply_beacon_rows)
        self.sig_busy.connect(self._set_busy)
        self.sig_status.connect(self._status)
        self.sig_connection.connect(self._set_connection)
        self.sig_disconnected.connect(self._set_disconnected)
        self.sig_quit.connect(lambda: self._quit(prompt=False))
        self.sig_force_quit.connect(self._forced_quit)
        self.sig_post.connect(self._run_on_main)

        # 7. Build UI
        self._build_menu()
        self._build_central()
        self._build_status_bar()
        self._bind_shortcuts()

        # 8. Install input/getpass interceptors
        self._orig_builtin_input = builtins.input
        self._orig_getpass = _getpass_mod.getpass
        builtins.input = self._gui_input              # type: ignore
        _getpass_mod.getpass = self._gui_getpass      # type: ignore

        # 9. Worker threads
        self._worker = threading.Thread(
            target=self._worker_loop, name='gui-command-worker',
            daemon=True)
        self._worker.start()
        self._chat_worker = threading.Thread(
            target=self._chat_worker_loop, name='gui-chat-worker',
            daemon=True)
        self._chat_worker.start()

        # 10. Queue pump (QTimer runs on the main thread)
        self._pump = QTimer(self)
        self._pump.timeout.connect(self._poll_queues)
        self._pump.start(80)

        # 11. Clock
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._tick_clock)
        self._clock_timer.start(1000)
        self._tick_clock()

        # 12. Auto-refresh
        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._auto_refresh)
        self._auto_timer.start(self.REFRESH_MS)

    # ==================================================================
    # Main-thread dispatcher (worker → GUI)

    @Slot(object)
    def _run_on_main(self, fn) -> None:
        try:
            fn()
        except Exception as exc:
            import traceback
            self._on_log(f"main-thread callback error: {exc}", 'err')
            if self.debug:
                for ln in traceback.format_exc().splitlines():
                    self._on_log(ln, 'meta')

    # ==================================================================
    # Menu

    def _build_menu(self) -> None:
        mb = self.menuBar()

        m_file = mb.addMenu('&File')
        act = QAction('Build agent…', self)
        act.setShortcut(QKeySequence('Ctrl+B'))
        act.triggered.connect(self._menu_build)
        m_file.addAction(act)

        act = QAction('Build from JSON config…', self)
        act.setShortcut(QKeySequence('Ctrl+Shift+B'))
        act.triggered.connect(self._menu_build_from_json)
        m_file.addAction(act)

        m_file.addSeparator()
        m_file.addAction('Export my config…',
                         lambda: self._submit('operators export'))
        m_file.addSeparator()
        act = QAction('Quit', self)
        act.setShortcut(QKeySequence('Ctrl+Q'))
        act.triggered.connect(self._quit)
        m_file.addAction(act)

        m_sess = mb.addMenu('&Session')
        act = QAction('Refresh beacons', self)
        act.setShortcut(QKeySequence('F5'))
        act.triggered.connect(self._refresh_beacons_async)
        m_sess.addAction(act)
        m_sess.addAction('Detach', lambda: self._submit('detach'))
        m_sess.addSeparator()
        act = QAction('Chat', self)
        act.setShortcut(QKeySequence('Ctrl+T'))
        act.triggered.connect(lambda: self._submit('chat'))
        m_sess.addAction(act)
        m_sess.addSeparator()
        m_sess.addAction('Killall --all…',
                         lambda: self._submit('killall --all'))
        m_sess.addAction('Killall --stale…',
                         lambda: self._submit('killall --stale'))

        m_view = mb.addMenu('&View')
        act = QAction('Log tab', self)
        act.setShortcut(QKeySequence('Ctrl+1'))
        act.triggered.connect(lambda: self._select_tab(0))
        m_view.addAction(act)
        act = QAction('Chat tab', self)
        act.setShortcut(QKeySequence('Ctrl+2'))
        act.triggered.connect(lambda: self._select_tab(1))
        m_view.addAction(act)
        m_view.addSeparator()
        act = QAction('Clear log', self)
        act.setShortcut(QKeySequence('Ctrl+L'))
        act.triggered.connect(self._clear_log)
        m_view.addAction(act)
        m_view.addAction('Clear chat', self._clear_chat)

        m_tools = mb.addMenu('&Tools')
        m_tools.addAction('Command index',
                          lambda: self._submit('help'))
        m_tools.addAction('List beacons',
                          lambda: self._submit('beacons'))
        m_tools.addAction('Audit log',
                          lambda: self._submit('audit 50'))
        m_tools.addSeparator()
        m_tools.addAction('Credential vault',
                          lambda: self._submit('creds list'))
        m_tools.addAction('Loot store',
                          lambda: self._submit('loot list'))
        m_tools.addAction('C2 profiles',
                          lambda: self._submit('c2-profiles'))
        m_tools.addSeparator()
        m_tools.addAction('Set spawnto for attached beacon…',
                          lambda: self._prompt_spawnto(
                              self.client.current_beacon))
        m_tools.addSeparator()
        m_tools.addAction('Deadman status',
                          lambda: self._submit('deadman status'))
        m_tools.addAction('Operators',
                          lambda: self._submit('operators list'))

        m_help = mb.addMenu('&Help')
        m_help.addAction('About', self._about)

    # ==================================================================
    # Central widget

    def _build_central(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_header())

        divider = QWidget()
        divider.setObjectName('headerDivider')
        divider.setFixedHeight(1)
        outer.addWidget(divider)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(1)
        outer.addWidget(splitter, 1)

        splitter.addWidget(self._build_beacon_pane())
        splitter.addWidget(self._build_main_pane())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([240, 560])

    # ------------------------------------------------------------------
    # Header bar

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName('headerBar')
        bar.setFixedHeight(52)

        lay = QHBoxLayout(bar)
        lay.setContentsMargins(Sp.L, Sp.S, Sp.L, Sp.S)
        lay.setSpacing(0)

        # Brand
        glyph = QLabel('\u25c6')
        glyph.setObjectName('brandGlyph')
        lay.addWidget(glyph)
        lay.addSpacing(Sp.S)

        brand = QLabel('TORNADOC2')
        brand.setObjectName('brandWord')
        lay.addWidget(brand)
        lay.addSpacing(Sp.S)

        sub = QLabel('CONSOLE')
        sub.setObjectName('brandSub')
        lay.addWidget(sub)
        lay.addSpacing(Sp.XL)

        # Connection info
        self.header_conn = QLabel('connecting…')
        self.header_conn.setObjectName('connInfo')
        lay.addWidget(self.header_conn)
        lay.addStretch(1)

        # Right side: status dot, status pill, role badge
        self.status_dot = StatusDot()
        lay.addWidget(self.status_dot)
        lay.addSpacing(Sp.XS)

        self.status_pill = QLabel('connecting')
        self.status_pill.setObjectName('statusPill')
        self.status_pill.setProperty('state', 'connecting')
        lay.addWidget(self.status_pill)
        lay.addSpacing(Sp.M)

        self.role_badge = QLabel('—')
        self.role_badge.setObjectName('roleBadge')
        lay.addWidget(self.role_badge)

        return bar

    def _set_connection(self, host: str, role: str) -> None:
        self.header_conn.setText(host)
        self.role_badge.setText(role.upper())
        self.status_pill.setText('online')
        self.status_pill.setProperty('state', 'online')
        self._repolish(self.status_pill)
        self.status_dot.set_color(Palette.OK)

    def _set_disconnected(self) -> None:
        self.status_pill.setText('offline')
        self.status_pill.setProperty('state', 'offline')
        self._repolish(self.status_pill)
        self.status_dot.set_color(Palette.ERR)

    @staticmethod
    def _repolish(w: QWidget) -> None:
        w.style().unpolish(w)
        w.style().polish(w)

    # ------------------------------------------------------------------
    # Sidebar

    def _build_beacon_pane(self) -> QWidget:
        pane = QWidget()
        pane.setObjectName('sidebar')
        pane.setMinimumHeight(140)

        lay = QVBoxLayout(pane)
        lay.setContentsMargins(Sp.L, Sp.M, Sp.L, Sp.S)
        lay.setSpacing(Sp.S)

        # ── Toolbar row ──────────────────────────────────────
        head = QHBoxLayout()
        head.setSpacing(Sp.S)

        # A small accent dot before the section label. Same
        # visual grammar as the ◈ in the brand strip — a
        # coloured glyph on the left of a text label marks a
        # region the eye should land on.
        dot = QLabel('\u25cf')
        dot.setStyleSheet(
            f'color: {Palette.ACCENT}; font-size: 8pt; '
            f'background: transparent;')
        head.addWidget(dot)

        lbl = QLabel('BEACONS')
        lbl.setObjectName('sectionLabel')
        head.addWidget(lbl)

        self.beacon_count_lbl = QLabel('0')
        self.beacon_count_lbl.setObjectName('sectionCount')
        head.addWidget(self.beacon_count_lbl)

        head.addSpacing(Sp.M)

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText('filter beacons…')
        self.search_entry.textChanged.connect(
            lambda _t: self._on_search_change())

        glyph = QLabel('\u2315')
        glyph.setFont(_f_ui(11))

        search_wrap = _FocusFrame(self.search_entry, name='searchBox')
        search_lay = QHBoxLayout(search_wrap)
        search_lay.setContentsMargins(0, 0, 6, 0)
        search_lay.setSpacing(0)
        search_lay.addWidget(glyph)
        search_lay.addWidget(self.search_entry, 1)
        search_wrap.setMaximumWidth(340)
        search_wrap.setMinimumWidth(220)
        head.addWidget(search_wrap)

        head.addStretch(1)

        attach = QPushButton('Attach')
        attach.setObjectName('primary')
        attach.clicked.connect(self._attach_selected)
        head.addWidget(attach)

        detach = QPushButton('Detach')
        detach.clicked.connect(lambda: self._submit('detach'))
        head.addWidget(detach)

        refresh = QPushButton('Refresh')
        refresh.setObjectName('ghost')
        refresh.clicked.connect(self._refresh_beacons_async)
        head.addWidget(refresh)

        lay.addLayout(head)

        # ── Beacon table ─────────────────────────────────────
        self.tree = _BeaconTree()
        self.tree.set_empty_text(
            'waiting for beacons\n'
            'the list updates every few seconds')
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(['BEACON', 'USER@HOST', 'OS',
                                   'LAST', 'VIEW'])
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(
            QTreeWidget.SelectionMode.SingleSelection)
        self.tree.setAlternatingRowColors(False)
        self.tree.setSortingEnabled(False)
        self.tree.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(
            self._on_tree_context)
        self.tree.itemDoubleClicked.connect(
            lambda *_: self._attach_selected())
        self.tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)

        # Column sizing. USER@HOST stretches to fill the rest;
        # everything else sizes to its content so a header like
        # "win/amd64" never truncates to "wi...64". The trade is
        # that OS and LAST re-measure on every refresh; for a
        # fleet of tens that is invisible.
        hdr = self.tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.setColumnWidth(0, 200)   # BEACON  (dot + id + alias)
        hdr.sectionClicked.connect(self._sort_by)
        hdr.setSectionsClickable(True)

        lay.addWidget(self.tree, 1)
        return pane

    # ------------------------------------------------------------------
    # Main pane (tabs + input bar)

    def _build_main_pane(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(Sp.L, Sp.L, Sp.L, Sp.L)
        lay.setSpacing(Sp.M)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)

        # ── Log tab
        log_tab = QWidget()
        log_lay = QVBoxLayout(log_tab)
        log_lay.setContentsMargins(0, 0, 0, 0)
        self.log_widget = QPlainTextEdit()
        self.log_widget.setObjectName('logView')
        self.log_widget.setReadOnly(True)
        self.log_widget.setFont(_f_mono(10))
        self.log_widget.setMaximumBlockCount(50000)
        log_lay.addWidget(self.log_widget)
        self.tabs.addTab(log_tab, '  Log  ')

        # ── Chat tab
        chat_tab = QWidget()
        chat_lay = QVBoxLayout(chat_tab)
        chat_lay.setContentsMargins(0, 0, 0, 0)
        chat_lay.setSpacing(0)

        # Pinned topic banner
        self.chat_topic = QWidget()
        self.chat_topic.setObjectName('chatTopic')
        ct_lay = QHBoxLayout(self.chat_topic)
        ct_lay.setContentsMargins(Sp.M, Sp.S, Sp.M, Sp.S)
        self.chat_topic_lbl = QLabel('')
        self.chat_topic_lbl.setWordWrap(True)
        ct_lay.addWidget(self.chat_topic_lbl)
        self.chat_topic.setVisible(False)
        chat_lay.addWidget(self.chat_topic)

        self.chat_widget = QPlainTextEdit()
        self.chat_widget.setObjectName('chatView')
        self.chat_widget.setReadOnly(True)
        self.chat_widget.setFont(_f_mono(10))
        chat_lay.addWidget(self.chat_widget, 1)
        self.tabs.addTab(chat_tab, '  Chat  ')

        # ── Input bar
        self.prompt_lbl = QLabel('›')
        self.prompt_lbl.setFont(_f_mono(11, bold=True))
        self.prompt_lbl.setStyleSheet(
            f'color: {Palette.ACCENT}; background: transparent;')
        self.prompt_lbl.setMinimumWidth(110)

        self.input_entry = _HistoryLineEdit()
        self.input_entry.setFont(_f_mono(11))
        self.input_entry.returnPressed.connect(self._on_submit)

        self.send_btn = QPushButton('Send')
        self.send_btn.setObjectName('primary')
        self.send_btn.setMinimumWidth(80)
        self.send_btn.clicked.connect(self._on_submit)

        inp_wrap = _FocusFrame(self.input_entry, name='inputBar')
        inp_lay = QHBoxLayout(inp_wrap)
        inp_lay.setContentsMargins(Sp.M, 2, 6, 2)
        inp_lay.setSpacing(4)
        inp_lay.addWidget(self.prompt_lbl)
        inp_lay.addWidget(self.input_entry, 1)
        inp_lay.addWidget(self.send_btn)
        lay.addWidget(inp_wrap)

        self.tabs.currentChanged.connect(
            lambda _i: self._on_tab_change())

        self._chat_tab_active = (self.tabs.currentIndex() == 1)

        self.input_entry.set_history(self._history)
        self.input_entry.setFocus()
        return pane

    # ------------------------------------------------------------------
    # Status bar

    def _build_status_bar(self) -> None:
        sb = QStatusBar()
        sb.setSizeGripEnabled(False)
        self.setStatusBar(sb)

        self.status_lbl = QLabel('initialising…')
        self.status_lbl.setFont(_f_mono(9))
        self.status_lbl.setStyleSheet(
            f'color: {Palette.TEXT_MUTED};')
        sb.addWidget(self.status_lbl, 1)

        self.clock_lbl = QLabel('')
        self.clock_lbl.setFont(_f_mono(9))
        self.clock_lbl.setStyleSheet(f'color: {Palette.TEXT_FAINT};')
        sb.addPermanentWidget(self.clock_lbl)

    def _tick_clock(self) -> None:
        self.clock_lbl.setText(time.strftime('%H:%M:%S'))

    # ------------------------------------------------------------------
    # Shortcuts

    def _bind_shortcuts(self) -> None:
        QShortcut(QKeySequence('Ctrl+Q'), self, activated=self._quit)
        QShortcut(QKeySequence('Ctrl+L'), self,
                  activated=self._clear_log)
        QShortcut(QKeySequence('Ctrl+B'), self,
                  activated=self._menu_build)
        QShortcut(QKeySequence('Ctrl+T'), self,
                  activated=lambda: self._submit('chat'))
        QShortcut(QKeySequence('Ctrl+1'), self,
                  activated=lambda: self._select_tab(0))
        QShortcut(QKeySequence('Ctrl+2'), self,
                  activated=lambda: self._select_tab(1))
        QShortcut(QKeySequence('F5'), self,
                  activated=self._refresh_beacons_async)
        QShortcut(QKeySequence('Ctrl+Shift+W'), self,
                  activated=self._prompt_spawnto_selected)
        QShortcut(QKeySequence('Ctrl+C'), self,
                  context=Qt.ShortcutContext.ApplicationShortcut,
                  activated=self._on_copy_or_clear)
        QShortcut(QKeySequence('Ctrl+Shift+C'), self,
                  context=Qt.ShortcutContext.ApplicationShortcut,
                  activated=self._on_copy_only)
        QShortcut(QKeySequence('Ctrl+V'), self,
                  context=Qt.ShortcutContext.ApplicationShortcut,
                  activated=self._on_paste)
        QShortcut(QKeySequence('Ctrl+Shift+V'), self,
                  context=Qt.ShortcutContext.ApplicationShortcut,
                  activated=self._on_paste)

    def _select_tab(self, idx: int) -> None:
        self.tabs.setCurrentIndex(idx)

    def _on_tab_change(self) -> None:
        self._chat_tab_active = (self.tabs.currentIndex() == 1)
        self._update_input_prompt()
        self._update_input_state()

    # ------------------------------------------------------------------
    # Ctrl+C — copy or clear, context-dependent

    def _on_copy_or_clear(self) -> None:
        """Ctrl+C behaviour.

        Priority order:

          1. The focused widget, if it has a selection. That is
             almost always the input bar, but it can also be a
             QLineEdit inside a modal dialog that has not grabbed
             the shortcut — Qt routes keystrokes through the
             focused widget first, so this handler only runs when
             the focused widget did not accept the event.
          2. A selection in the Log or Chat tab. Read whichever is
             active; the inactive tab's selection is not visible
             to the operator and should not be silently copied.
          3. The input bar contains text — clear it, matching the
             CLI's Ctrl+C-at-prompt behaviour.
          4. Otherwise, no-op.
        """
        focused = QApplication.focusWidget()
        if focused is not None:
            if hasattr(focused, 'selectedText'):
                sel = focused.selectedText()
                if sel:
                    QApplication.clipboard().setText(sel)
                    return
            if hasattr(focused, 'textCursor'):
                cur = focused.textCursor()
                if cur is not None and cur.hasSelection():
                    QApplication.clipboard().setText(
                        cur.selectedText())
                    return

        active = self.chat_widget if self._on_chat_tab() \
                 else self.log_widget
        cur = active.textCursor()
        if cur is not None and cur.hasSelection():
            QApplication.clipboard().setText(cur.selectedText())
            return

        if self.input_entry.text():
            self.input_entry.setText('')
            self.input_entry.setFocus()
            return

    def _on_copy_only(self) -> None:
        """Ctrl+Shift+C — copy without the clear-if-empty fallback.

        Matches the terminal convention: Shift forces the copy
        action. An operator who wants to copy a selection and
        knows there is nothing to copy gets a no-op rather than
        their input bar being wiped.
        """
        focused = QApplication.focusWidget()
        if focused is not None:
            if hasattr(focused, 'selectedText'):
                sel = focused.selectedText()
                if sel:
                    QApplication.clipboard().setText(sel)
                    return
            if hasattr(focused, 'textCursor'):
                cur = focused.textCursor()
                if cur is not None and cur.hasSelection():
                    QApplication.clipboard().setText(
                        cur.selectedText())
                    return

        active = self.chat_widget if self._on_chat_tab() \
                 else self.log_widget
        cur = active.textCursor()
        if cur is not None and cur.hasSelection():
            QApplication.clipboard().setText(cur.selectedText())

    def _on_paste(self) -> None:
        """Ctrl+V behaviour.

        Priority order:

          1. A focused editable widget — QLineEdit, QPlainTextEdit,
             QComboBox's line edit — receives the paste natively.
             This is the same path Qt's default Ctrl+V binding
             takes, so the handler only matches the default rather
             than replacing it.
          2. No editable widget focused (the Log or Chat tab holds
             focus, both read-only): paste into the input bar and
             give it focus. Without this, the keystroke would be
             swallowed by the read-only widget and the operator
             would see nothing happen. A read-only QPlainTextEdit's
             ``paste()`` is a no-op, so the check must test the
             read-only flag, not just the type.
          3. Otherwise, no-op.

        The multiline paste dialog is a separate top-level window;
        while it is open, the focused widget is inside the dialog
        and case 1 applies. The dialog's own Ctrl+V works without
        the ApplicationShortcut registered here.
        """
        focused = QApplication.focusWidget()
        if isinstance(focused, QLineEdit) and not focused.isReadOnly():
            focused.paste()
            return
        if isinstance(focused, QPlainTextEdit) \
                and not focused.isReadOnly():
            focused.paste()
            return

        self.input_entry.paste()
        self.input_entry.setFocus()

    # ==================================================================
    # Lifecycle

    def showEvent(self, ev) -> None:
        super().showEvent(ev)
        if self._init_started:
            return
        self._init_started = True
        threading.Thread(target=self._initialise,
                         name='gui-init', daemon=True).start()

    def closeEvent(self, ev) -> None:
        """Window-close handler.

        Fires on the title-bar X and on `app.quit()`. The same
        confirmation the `quit` command uses is asked here, so both
        paths behave identically. On confirmation, `_shutdown_all`
        runs the cleanup once and lets the event through; a second
        close attempt (from `_quit`, which calls `self.close()` after
        already running `_shutdown_all`) skips the prompt because
        `_shutdown` is already set.
        """
        if not self._shutdown.is_set():
            ans = QMessageBox.question(
                self, 'Quit',
                'Disconnect from the team server?',
                QMessageBox.StandardButton.Yes
                | QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                ev.ignore()
                return
        self._shutdown_all()
        ev.accept()

    def _shutdown_all(self) -> None:
        """Stop every background thread, restore the process-wide
        substitutions, and let the window close.

        Idempotent — safe to call from `closeEvent` and from
        `_quit` and `_forced_quit` in the same shutdown. The first
        call does the work; later calls return immediately because
        `_shutdown` is set.
        """
        if self._shutdown.is_set():
            return
        self._shutdown.set()

        if self._chat is not None:
            try:
                self._chat.stop()
            except Exception:
                pass
        if getattr(self.client, '_result_poller', None) is not None:
            try:
                self.client._result_poller.stop()
            except Exception:
                pass

        builtins.input = self._orig_builtin_input
        _getpass_mod.getpass = self._orig_getpass
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr

        if getattr(self.client, '_socks_proxy', None):
            try:
                self.client._socks_proxy.stop()
            except Exception:
                pass

    def _quit(self, prompt: bool = True) -> None:
        """Quit the application.

        Called from Ctrl+Q, from the File menu, and from the
        `exit` / `quit` command dispatched in `_dispatch_line`.
        When `prompt` is True (the default) a confirmation dialog
        is shown; the `sig_quit` connection calls with
        `prompt=False` because the operator already typed an
        explicit quit command and does not need to be asked twice.
        """
        if prompt and not self._shutdown.is_set():
            ans = QMessageBox.question(
                self, 'Quit',
                'Disconnect from the team server?',
                QMessageBox.StandardButton.Yes
                | QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                return
        self._shutdown_all()
        self.close()

    def _forced_quit(self) -> None:
        """Exit without the yes/no prompt.

        Called from the worker thread (via `sig_force_quit`) when a
        self password change has already rewritten the config; the
        operator needs to restart to pick it up. A short
        informational dialog replaces the usual prompt so the
        operator is told *why* the window is closing rather than
        being asked whether they meant it.
        """
        try:
            QMessageBox.information(
                self, 'Restart required',
                'Your password was changed and the config file '
                'has been rewritten with the new derivation '
                'parameters.\n\n'
                'The client will now close. Start it again with '
                'the same config path to continue.')
        except Exception:
            pass
        self._shutdown_all()
        self.close()

    # ==================================================================
    # Initialise (worker thread)

    def _initialise(self) -> None:
        try:
            self.client.banner()
        except Exception as exc:
            self._log(f"connection failed: {exc}", 'err')
            self.sig_disconnected.emit()
            self.sig_status.emit('offline')
            return

        self._connected = True
        host = (f"{self.cfg.get('server_host', '?')}:"
                f"{self.cfg.get('server_port', '?')}")
        self.sig_connection.emit(host, self.client.role)
        self.sig_post.emit(self._refresh_beacons_async)
        self.sig_post.emit(self._update_status)
        self._log('connected', 'ok')

        if 'chat.use' in self.client.caps:
            self._chat = _GuiChat(self)
            threading.Thread(target=self._chat.start,
                             name='gui-chat-startup',
                             daemon=True).start()
            self.sig_post.emit(self._update_input_prompt)
        else:
            self._log('chat.use not granted to this role; '
                      'chat is disabled', 'warn')

    def _auto_refresh(self) -> None:
        if (self._connected
                and not self._shutdown.is_set()
                and not self._busy):
            self._refresh_beacons_async()

    def _refresh_beacons_async(self) -> None:
        if not self._connected or self._busy:
            return
        self._command_q.put(('callable', self._fetch_beacons_worker))

    def _fetch_beacons_worker(self) -> None:
        try:
            rows = self.client.tp.post(
                '/api/v1/beacons',
                {'current': self.client.current_beacon})
        except Exception as exc:
            self._log(f"beacons refresh failed: {exc}", 'err')
            return
        rows = list(rows or [])
        self.client._beacon_cache = rows
        self.client._beacon_ids = [str(b['id']) for b in rows]
        self.sig_beacons.emit(rows)

    @Slot(object)
    def _apply_beacon_rows(self, rows) -> None:
        self._beacon_rows = rows
        self._render_beacon_tree()

    # ==================================================================
    # Beacon tree

    def _render_cached_beacons(self) -> None:
        rows = list(getattr(self.client, '_beacon_cache', []) or [])
        self._beacon_rows = rows
        self._render_beacon_tree()

    def _on_search_change(self) -> None:
        self._filter_text = self.search_entry.text().strip().lower()
        self._render_beacon_tree()

    def _sort_by(self, col: int) -> None:
        keys = ['id', 'host', 'plat', 'age', 'view']
        if 0 <= col < len(keys):
            key = keys[col]
            if self._sort_col == key:
                self._sort_reverse = not self._sort_reverse
            else:
                self._sort_col = key
                self._sort_reverse = False
            self._render_beacon_tree()

    def _render_beacon_tree(self) -> None:
        self.tree.clear()

        if self._filter_text:
            self.tree.set_empty_text(
                f'no beacons match "{self._filter_text}"')
        else:
            self.tree.set_empty_text(
                'waiting for beacons\n'
                'the list updates every few seconds')

        rows = list(self._beacon_rows)

        if self._filter_text:
            def match(b) -> bool:
                hay = ' '.join(str(b.get(k, '') or '') for k in (
                    'id', 'display_name', 'alias', 'os', 'arch'))
                return self._filter_text in hay.lower()
            rows = [b for b in rows if match(b)]

        col = self._sort_col
        rev = self._sort_reverse

        def keyf(b):
            if col == 'id':
                return b.get('id', 0)
            if col == 'view':
                return len(b.get('viewers') or [])
            if col == 'age':
                return b.get('last_seen_age', 0)
            if col == 'alias':
                return b.get('alias') or ''
            if col == 'host':
                return b.get('display_name') or ''
            if col == 'plat':
                return b.get('os') or ''
            return b.get('id', 0)

        try:
            rows.sort(key=keyf, reverse=rev)
        except TypeError:
            rows.sort(key=lambda b: str(b.get('id', 0)),
                      reverse=rev)

        for b in rows:
            age = b.get('last_seen_age', 0)
            if age < 60:
                age_s = f"{age}s"
            elif age < 3600:
                age_s = f"{age // 60}m"
            elif age < 86400:
                age_s = f"{age // 3600}h"
            else:
                age_s = f"{age // 86400}d"

            # Viewers column. The count is what matters at a
            # glance; the name is a bonus when there is exactly
            # one. Two or more is a "+N" because the operator
            # will hover for the full list, and squeezing names
            # into 62px is worse than a compact count.
            viewers = b.get('viewers') or []
            if not viewers:
                view_text = '—'
            elif len(viewers) == 1:
                view_text = viewers[0].get('name', '?')
            else:
                view_text = f"+{len(viewers)}"

            # Platform as a compact win/amd64, lin/arm64, mac/…
            # The full string lives in the tooltip.
            os_raw = (b.get('os') or '').lower()
            os_short = {
                'windows': 'win',
                'linux':   'lin',
                'darwin':  'mac',
                'freebsd': 'bsd',
            }.get(os_raw, os_raw[:3] if os_raw else '?')
            arch_raw = (b.get('arch') or '')
            plat = f"{os_short}/{arch_raw}" if arch_raw else os_short

            live = b.get('alive')
            dot = '●' if live else '○'

            # ID cell carries the alias as a suffix when one is
            # set: "● 1001 dc01". No separate column, no wasted
            # horizontal space on an empty column.
            alias = (b.get('alias') or '').strip()
            if alias:
                beacon_cell = f"{dot}  {b['id']}  {alias}"
            else:
                beacon_cell = f"{dot}  {b['id']}"

            item = QTreeWidgetItem([
                beacon_cell,
                b.get('display_name') or '?',
                plat,
                age_s,
                view_text,
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, b['id'])

            # ── Tooltip: full identity on every column ───────
            addr = b.get('last_addr') or '—'
            sleep = b.get('sleep_interval', 0)
            fp = (b.get('fingerprint') or '')[:16]
            checkins = b.get('checkins', 0)
            spawnto = (b.get('spawnto') or '').strip()
            if not spawnto:
                spawnto_note = '(default worker path)'
            elif spawnto == 'self':
                spawnto_note = 'self (explicit)'
            else:
                spawnto_note = spawnto

            tip = (
                f"beacon #{b['id']}\n"
                f"alias       : {alias or '—'}\n"
                f"host        : {b.get('display_name', '?')}\n"
                f"platform    : {b.get('os','?')}/"
                f"{arch_raw}\n"
                f"address     : {addr}\n"
                f"sleep       : {sleep}s\n"
                f"check-ins   : {checkins}\n"
                f"last seen   : {age_s} ago\n"
                f"spawnto     : {spawnto_note}\n"
                f"fingerprint : {fp}…"
            )

            # ── Colours ──────────────────────────────────────
            # The BEACON cell carries the liveness signal: green
            # for an alive beacon, dim grey for stale. Everything
            # else is standard body text so the eye lands on the
            # dot first.
            if live:
                beacon_color = QColor(Palette.OK)
            else:
                beacon_color = QColor(Palette.TEXT_FAINT)
            body_color = QColor(Palette.TEXT)

            # Viewers: empty is dim, one viewer is a cyan name,
            # two or more is a bright amber +N. Matches the CLI's
            # beacons table so an operator who has used one
            # recognises the other.
            if not viewers:
                view_color = QColor(Palette.TEXT_FAINT)
            elif len(viewers) == 1:
                view_color = QColor(Palette.CYAN)
            else:
                view_color = QColor(Palette.WARN)

            for c in range(5):
                item.setToolTip(c, tip)

            if live:
                tint = QColor(Palette.OK)
                tint.setAlpha(14)
                for c in range(5):
                    item.setBackground(c, QBrush(tint))

            item.setForeground(0, QBrush(beacon_color))
            item.setForeground(1, QBrush(body_color))
            item.setForeground(2, QBrush(QColor(Palette.TEXT_MUTED)))
            item.setForeground(3, QBrush(QColor(Palette.TEXT_MUTED)))
            item.setForeground(4, QBrush(view_color))

            self.tree.addTopLevelItem(item)

        alive_n = sum(1 for b in self._beacon_rows if b.get('alive'))
        stale_n = len(self._beacon_rows) - alive_n
        if self._filter_text:
            self.beacon_count_lbl.setText(
                f"·  {len(rows)} / {len(self._beacon_rows)} shown")
        elif stale_n:
            self.beacon_count_lbl.setText(
                f"·  {alive_n} live  ·  {stale_n} stale")
        else:
            self.beacon_count_lbl.setText(f"·  {alive_n}")

    def _selected_id(self) -> str:
        sel = self.tree.selectedItems()
        if not sel:
            return ''
        return str(sel[0].data(0, Qt.ItemDataRole.UserRole))

    def _attach_selected(self) -> None:
        sel = self._selected_id()
        if sel:
            self._submit(f"use {sel}")

    def _on_tree_context(self, pos: QPoint) -> None:
        item = self.tree.itemAt(pos)
        if item is None:
            return
        self.tree.setCurrentItem(item)

        sel = self._selected_id()
        fp = self._selected_fingerprint()

        menu = QMenu(self)
        menu.addAction('Attach', self._attach_selected)
        menu.addAction('Show info',
                       lambda: self._submit(f"use {sel}"))
        menu.addSeparator()

        act = menu.addAction('Copy ID')
        act.setEnabled(bool(sel))
        act.triggered.connect(
            lambda: QApplication.clipboard().setText(sel))
        act = menu.addAction('Copy fingerprint')
        act.setEnabled(bool(fp))
        act.triggered.connect(
            lambda: QApplication.clipboard().setText(fp))

        menu.addSeparator()
        menu.addAction('Set alias…', self._ctx_set_alias)
        menu.addAction('Set spawnto…',
                       lambda: self._prompt_spawnto(sel))
        menu.addSeparator()
        menu.addAction('Kill', lambda: self._ctx_action('kill'))
        menu.addAction('Forget', lambda: self._ctx_action('forget'))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _selected_fingerprint(self) -> str:
        """Return the fingerprint of the selected beacon, or ''.

        Reads from the in-memory cache rather than stashing the
        value on the tree item, so a beacon forgotten and re-added
        between renders does not leave a stale fingerprint behind
        on an old QTreeWidgetItem.
        """
        sel = self._selected_id()
        if not sel:
            return ''
        for b in self._beacon_rows:
            if str(b.get('id')) == sel:
                return b.get('fingerprint') or ''
        return ''

    def _ctx_action(self, verb: str) -> None:
        sel = self._selected_id()
        if not sel or verb not in ('kill', 'forget'):
            return
        if self._busy:
            self._log('(a command is already running — wait for it)',
                      'warn')
            return

        def _do():
            c = self.client
            c._cmd_use(['use', sel])
            self.sig_post.emit(self._render_cached_beacons)
            self.sig_post.emit(self._update_status)
            c._cmd_beacon([verb])
            self.sig_post.emit(self._render_cached_beacons)
            self.sig_post.emit(self._update_status)

        self._command_q.put(('callable', _do))

    def _ctx_set_alias(self) -> None:
        sel = self._selected_id()
        if not sel:
            return
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(
            self, 'Set alias', f'Alias for beacon #{sel}:')
        if not ok or not name:
            return
        self._submit(f"use {sel}")
        self._submit(f"alias {name}")

    def _prompt_spawnto_selected(self) -> None:
        """Open the spawnto prompt for the currently selected
        beacon. Bound to Ctrl+Shift+W so an operator whose hands
        are already on the tree does not have to reach for the
        mouse."""
        self._prompt_spawnto(self._selected_id())

    def _prompt_spawnto(self, bid: str) -> None:
        """Prompt for a spawnto path and dispatch it.

        The verb is a server-side intercept: the listener's
        `_apply_local_verb` mutates the session and returns the
        confirmation inline, so the operator sees the resulting
        value immediately rather than on the next beacon poll.
        The GUI does not need to know any of that — it submits
        the same `spawnto <path>` line the CLI would, and the
        response arrives through the normal task-result path.

        Two empty inputs are meaningful:

          * A cancelled dialog — the operator changed their
            mind, nothing is submitted.
          * An empty string typed and accepted — the operator
            wants to clear the current spawnto back to the
            default worker path. This sends `spawnto -`,
            matching the server's clear sentinel.

        Anything else is passed through verbatim. The server
        validates length and control characters and refuses the
        reserved word "self"; a syntactically valid but
        nonexistent path is accepted by the server and fails on
        the target with a specific error, which is the right
        layer for that check.
        """
        if not bid:
            self._log('select a beacon first', 'warn')
            return
        if self._busy:
            self._log('(a command is already running — wait for it)',
                      'warn')
            return

        from PySide6.QtWidgets import QInputDialog
        path, ok = QInputDialog.getText(
            self, f'Spawnto for beacon #{bid}',
            'Path to the sacrificial process that '
            'execute-assembly should spawn.\n\n'
            'Leave blank and press OK to clear (revert to the '
            'default worker path under %LOCALAPPDATA%).')
        if not ok:
            return

        path = path.strip()
        if path == '':
            verb_args = ['spawnto', '-']
        else:
            verb_args = ['spawnto', path]

        self._submit(f"use {bid}")
        self._submit(' '.join(verb_args))
        self._log(f"spawnto for #{bid}: "
                  f"{path or '<default>'}", 'meta')

    # ==================================================================
    # Input submission

    def _on_submit(self) -> None:
        line = self.input_entry.text()
        if not line.strip():
            return
        self.input_entry.setText('')

        if self._on_chat_tab():
            if self._chat is None:
                self._chat_print('chat is not available for this role')
                return
            self._chat_send_q.put(line)
            return

        line = line.strip()
        if not self._history or self._history[-1] != line:
            self._history.append(line)
        self.input_entry.reset_cursor()
        self._submit(line)

    def _on_chat_tab(self) -> bool:
        """Return the cached active-tab state.

        Called from both the main thread and the chat poller
        worker. Reads a plain Python attribute rather than
        ``self.tabs.currentIndex()`` — Qt widgets must only be
        touched from the thread that owns them."""
        return self._chat_tab_active

    def _chat_print(self, text: str) -> None:
        self._chat_q.put(('raw', text))

    def _update_input_prompt(self) -> None:
        if self._on_chat_tab() and self._chat is not None:
            peer = self._chat._dm_peer
            if peer:
                self.prompt_lbl.setText(f'chat→{peer} \u203a')
                self.prompt_lbl.setStyleSheet(
                    f'color: {Palette.MAGENTA}; background: transparent;')
            else:
                self.prompt_lbl.setText('chat \u203a')
                self.prompt_lbl.setStyleSheet(
                    f'color: {Palette.PURPLE}; background: transparent;')
            return
        bid = self.client.current_beacon
        if bid:
            self.prompt_lbl.setText(f'#{bid} \u203a')
            self.prompt_lbl.setStyleSheet(
                f'color: {Palette.ACCENT}; '
                f'background: transparent;')
        else:
            self.prompt_lbl.setText('no beacon \u203a')
            self.prompt_lbl.setStyleSheet(
                f'color: {Palette.TEXT_FAINT}; '
                f'background: transparent;')

    def _update_input_state(self) -> None:
        if self._on_chat_tab():
            self.input_entry.setEnabled(True)
            return
        self.input_entry.setEnabled(not self._busy)

    def _submit(self, line: str) -> None:
        if self._busy:
            self._log('(a command is already running — wait for it)',
                      'warn')
            return
        self._command_q.put(('line', line))

    # ==================================================================
    # Worker threads

    def _worker_loop(self) -> None:
        while not self._shutdown.is_set():
            try:
                item = self._command_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            kind, payload = item
            self._busy = True
            self.sig_busy.emit(True)
            try:
                if kind == 'line':
                    self._dispatch_line(payload)
                elif kind == 'callable':
                    payload()
            except self._repl._RestartRequired:
                self.sig_force_quit.emit()
            except SystemExit:
                pass
            except Exception as exc:
                import traceback
                self._log(f"error: {exc}", 'err')
                if self.debug:
                    for ln in traceback.format_exc().splitlines():
                        self._log(ln, 'meta')
            finally:
                self._busy = False
                self.sig_busy.emit(False)

    def _chat_worker_loop(self) -> None:
        while not self._shutdown.is_set():
            try:
                line = self._chat_send_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if line is None:
                break
            if self._chat is None:
                continue
            try:
                self._chat.handle(line)
            except Exception as exc:
                self._log(f"chat error: {exc}", 'err')

    @Slot(bool)
    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        try:
            self._update_input_state()
        except Exception:
            pass
        if not busy and not self._on_chat_tab():
            self.input_entry.setFocus()

    # ==================================================================
    # Command dispatch

    def _dispatch_line(self, line: str) -> None:
        c = self.client
        parts = line.split()
        if not parts:
            return
        cmd = parts[0].lower()

        if cmd in ('exit', 'quit', 'q'):
            self.sig_quit.emit()
            return
        if cmd in ('help', '?'):
            c._help()
        elif cmd in ('clear', 'cls'):
            self.sig_post.emit(self._clear_log)
        elif cmd == 'killall':
            c._cmd_killall(parts)
            self.sig_post.emit(self._render_cached_beacons)
        elif cmd == 'history':
            c._cmd_history(parts)
        elif cmd == 'build':
            if len(parts) > 1:
                c._cmd_build(parts)
            else:
                self._run_build_dialog()
        elif cmd in ('c2-profiles', 'c2p'):
            c._cmd_c2_profiles(parts)
        elif cmd == 'bofs':
            c._cmd_bofs(parts)
        elif cmd in ('beacons', 'bl'):
            c._cmd_beacons()
            self.sig_post.emit(self._render_cached_beacons)
        elif cmd == 'use':
            c._cmd_use(parts)
            self.sig_post.emit(self._render_cached_beacons)
            self.sig_post.emit(self._update_status)
        elif cmd == 'detach':
            c._cmd_detach()
            self.sig_post.emit(self._render_cached_beacons)
            self.sig_post.emit(self._update_status)
        elif cmd == 'info' and not c.current_beacon:
            c._cmd_info()
        elif cmd == 'caps':
            c._cmd_caps()
        elif cmd == 'audit':
            c._cmd_audit(parts)
        elif cmd == 'chat':
            self.sig_post.emit(lambda: self._select_tab(1))
        elif cmd == 'loot':
            c._cmd_loot(parts)
        elif cmd == 'creds':
            c._cmd_creds(parts)
        elif cmd == 'notes':
            c._cmd_notes(parts)
        elif cmd == 'webhooks':
            c._cmd_webhooks(parts)
        elif cmd == 'deadman':
            c._cmd_deadman(parts)
        elif cmd == 'halt':
            c._cmd_halt(parts)
        elif cmd == 'operators':
            c._cmd_operators(parts)
        elif c.current_beacon:
            c._cmd_beacon(parts)
            if cmd in ('sleep', 'workhours', 'kill', 'forget',
                       'migrate'):
                self.sig_post.emit(self._render_cached_beacons)
                self.sig_post.emit(self._update_status)
        elif cmd in c._verbs_for('beacon'):
            print(f"{cmd} is a beacon verb — attach first "
                  f"with `use <id>`")
        else:
            print(f"unknown command: {cmd} (try `help`)")

    # ==================================================================
    # Build dialog

    def _menu_build(self) -> None:
        if self._busy:
            self._log('(busy — try again when idle)', 'warn')
            return
        self._submit('build')

    def _menu_build_from_json(self) -> None:
        """Build an agent from a JSON config file.

        Mirrors the CLI's `build -c <file.json>` path: the file
        picker is native, but the JSON parser, the payload
        assembly, and the remote-build dispatch are the same code
        the CLI uses (`Client._cmd_build`). Nothing about the
        config schema, validation, or server contract is
        re-implemented here.
        """
        if self._busy:
            self._log('(a command is already running — wait for it)',
                      'warn')
            return
        path = self.pick_json_config('Build from JSON config')
        if not path:
            return
        self._log(f'build from config: {path}', 'meta')
        self._command_q.put(
            ('callable',
             lambda: self.client._cmd_build(['build', '-c', path])))

    def _build_dir_candidates(self) -> list:
        """Directories the file picker tries before falling back
        to CWD.

        Order:

          1. The last directory a config was loaded from.
          2. The repository root, if the current working
             directory looks like a checkout subdirectory — a
             `client/` or `beacon/` child.
          3. The operator's home directory.
          4. The current working directory, as a last resort.

        The first candidate that exists as a directory is used.
        Nothing walks the tree or scans file contents; the list
        is cheap to evaluate and correct for the common case of
        the operator launching the client from the checkout
        root.
        """
        cands = []
        if self._last_build_dir:
            cands.append(self._last_build_dir)
        cwd = os.getcwd()
        # If we are one level under the repo root — the usual
        # `client/` or `beacon/` subdirectory — offer the parent.
        parent = os.path.dirname(cwd)
        if parent and os.path.isdir(parent):
            cands.append(parent)
        home = os.path.expanduser('~')
        if home:
            cands.append(home)
        cands.append(cwd)

        seen = set()
        out = []
        for c in cands:
            rc = os.path.abspath(c)
            if rc in seen:
                continue
            seen.add(rc)
            if os.path.isdir(rc):
                out.append(rc)
        return out

    def pick_json_config(self, title: str) -> Optional[str]:
        """Open a native file picker filtered to JSON configs.

        Returns the selected path, or None if the operator
        cancels. Updates `_last_build_dir` on success so the next
        invocation opens in the same place.
        """
        from PySide6.QtWidgets import QFileDialog
        start = self._build_dir_candidates()[0]
        path, _ = QFileDialog.getOpenFileName(
            self, title, start,
            'JSON config (*.json);;All files (*)')
        if not path:
            return None
        self._last_build_dir = os.path.dirname(path) or start
        return path

    def _run_build_dialog(self) -> None:
        done = threading.Event()
        holder: dict = {}

        def open_dialog():
            dlg = _BuildDialog(self, self.client)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                holder['payload'] = dlg.result
            else:
                holder['payload'] = None
            done.set()

        self.sig_post.emit(open_dialog)
        done.wait()

        payload = holder.get('payload')
        if payload is None:
            self._log('build cancelled', 'meta')
            return
        self.client._do_remote_build(payload)

    # ==================================================================
    # Input / getpass interception

    def _gui_input(self, prompt: str = '') -> str:
        stripped = prompt.strip()

        if stripped == '|':
            if getattr(self, '_pending_multiline', None) is not None:
                self._pending_multiline = None
                return '.'
            try:
                result = self._show_multiline_dialog()
            except Exception:
                self._pending_multiline = None
                raise
            if result is None:
                self._pending_multiline = None
                raise EOFError
            self._pending_multiline = result
            return result

        event = threading.Event()
        slot: dict = {}
        self._input_q.put(('text', prompt, event, slot))
        event.wait()
        if slot.get('cancel'):
            raise EOFError
        return slot.get('value', '')

    def _show_multiline_dialog(self) -> Optional[str]:
        holder: dict = {}
        done = threading.Event()

        def show():
            dlg = _MultilineDialog(self)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                holder['result'] = dlg.result
            else:
                holder['result'] = None
            done.set()

        self.sig_post.emit(show)
        done.wait()
        return holder.get('result')

    def _gui_getpass(self, prompt: str = 'Password: ',
                     stream=None) -> str:
        event = threading.Event()
        slot: dict = {}
        self._input_q.put(('password', prompt, event, slot))
        event.wait()
        if slot.get('cancel'):
            raise EOFError
        return slot.get('value', '')

    def _poll_input_queue(self) -> None:
        try:
            while True:
                kind, prompt, event, slot = self._input_q.get_nowait()
                mask = (kind == 'password')
                dlg = _InputPrompt(self, prompt, mask=mask,
                                   title='Password' if mask else 'Input')
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    slot['value'] = dlg.result
                else:
                    slot['cancel'] = True
                event.set()
        except queue.Empty:
            pass

    # ==================================================================
    # Queue pumps

    def _poll_queues(self) -> None:
        pending_cr: Optional[str] = None

        try:
            budget = 800
            while budget > 0:
                item = self._stdout_q.get_nowait()
                budget -= 1
                if len(item) == 2:
                    kind, line = item
                    term = 'nl'
                else:
                    kind, line, term = item
                if kind != 'out':
                    continue
                if term == 'cr':
                    pending_cr = line
                else:
                    pending_cr = None
                    self._on_log(line, 'auto')
        except queue.Empty:
            pass

        if pending_cr is not None:
            self._on_log(pending_cr, 'auto')

        try:
            budget = 300
            while budget > 0:
                kind, payload = self._chat_q.get_nowait()
                budget -= 1
                if kind == 'msg':
                    self._append_chat_msg(payload)
                elif kind == 'topic':
                    self._update_chat_topic(payload)
                elif kind == 'raw':
                    self._append_chat_raw(payload)
        except queue.Empty:
            pass

        self._poll_input_queue()

    # ==================================================================
    # Log rendering

    def _classify(self, line: str) -> str:
        s = line.strip()
        if not s:
            return 'out'
        if s.startswith('──') or s.startswith('-- ') \
                or s.startswith('[*]'):
            return 'meta'
        if s.startswith('✓'):
            return 'ok'
        if s.startswith('✗') or s.startswith('error:') \
                or s.startswith('Error:'):
            return 'err'
        if s.startswith('warning:') or s.startswith('Warning:') \
                or '⚠' in s:
            return 'warn'
        return 'out'

    def _log_fmt(self, tag: str) -> QTextCharFormat:
        key = f'_logfmt_{tag}'
        f = getattr(self, key, None)
        if f is not None:
            return f
        color = {
            'out':  Palette.TEXT,
            'ok':   Palette.OK,
            'err':  Palette.ERR,
            'warn': Palette.WARN,
            'meta': Palette.TEXT_FAINT,
            'head': Palette.ACCENT,
        }.get(tag, Palette.TEXT)
        font = _f_mono(10)
        if tag == 'meta':
            font.setItalic(True)
        if tag == 'head':
            font.setWeight(QFont.Weight.Bold)
        f = _make_fmt(color, font)
        setattr(self, key, f)
        return f

    @Slot(str, str)
    def _on_log(self, line: str, tag: str) -> None:
        if self._shutdown.is_set():
            return
        line = _strip_ansi(line)

        # "auto" tag → classify
        if tag == 'auto':
            stripped = line.strip()
            if stripped.startswith('──') or stripped.startswith('-- '):
                content = stripped.strip('-─ ').strip()
                self._insert_log(f"  {content}", 'head')
                return
            self._insert_log(line, self._classify(line))
        else:
            self._insert_log(line, tag)

    def _insert_log(self, line: str, tag: str) -> None:
        try:
            cur = self.log_widget.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            cur.insertText(line + '\n', self._log_fmt(tag))
            self.log_widget.setTextCursor(cur)
            self.log_widget.ensureCursorVisible()
        except Exception:
            pass

    def _log(self, line: str, tag: str = 'out') -> None:
        """Safe from any thread."""
        if self._shutdown.is_set():
            return
        if threading.current_thread() is not threading.main_thread():
            self.sig_log.emit(line, tag)
            return
        self._on_log(line, tag)

    def _clear_log(self) -> None:
        self.log_widget.clear()

    def _clear_chat(self) -> None:
        self.chat_widget.clear()

    # ==================================================================
    # Status

    @Slot(str)
    def _status(self, s: str) -> None:
        self.status_lbl.setText(s)

    def _update_status(self) -> None:
        c = self.client
        bid = c.current_beacon
        if bid:
            state = '?'
            sleep = 0
            for b in getattr(c, '_beacon_cache', []):
                if b.get('id') == bid:
                    state = 'alive' if b.get('alive') else 'stale'
                    sleep = b.get('sleep_interval', 0)
                    break
            pending = 0
            if getattr(c, '_result_poller', None) is not None:
                try:
                    pending = c._result_poller.pending_count()
                except Exception:
                    pending = 0
            note = f"  ·  {pending} pending" if pending else ""
            self._status(
                f"beacon #{bid}  ·  {state}  ·  sleep={sleep}s{note}")
        else:
            self._status('no beacon attached')
        self._update_input_prompt()

    # ==================================================================
    # Chat rendering

    def _gui_chat_render(self, msg, redraw=None) -> None:
        self._chat_q.put(('msg', dict(msg)))

    def _gui_chat_render_topic(self, topic) -> None:
        self._chat_q.put(('topic', dict(topic or {})))

    def _chat_speaker_fmt(self, who: str) -> QTextCharFormat:
        key = f'_chatspk_{who}'
        f = getattr(self, key, None)
        if f is not None:
            return f
        font = _f_mono(10)
        font.setWeight(QFont.Weight.Bold)
        f = _make_fmt(_chat_hue(who), font)
        setattr(self, key, f)
        return f

    def _chat_fmt(self, tag: str) -> QTextCharFormat:
        key = f'_chatfmt_{tag}'
        f = getattr(self, key, None)
        if f is not None:
            return f
        if tag == 'body':
            f = _make_fmt(Palette.TEXT, _f_mono(10))
        elif tag == 'meta':
            f = _make_fmt(Palette.TEXT_FAINT, _f_mono(10))
        elif tag == 'mention':
            mf = _f_mono(10, bold=True)
            f = _make_fmt(Palette.WARN, mf)
        elif tag == 'dm':
            f = _make_fmt(Palette.PURPLE, _f_mono(10))
        elif tag == 'system':
            sf = _f_mono(10)
            sf.setItalic(True)
            f = _make_fmt(Palette.TEXT_FAINT, sf)
        elif tag == 'day':
            f = _make_fmt(Palette.ACCENT, _f_mono(10, bold=True))
        else:
            f = _make_fmt(Palette.TEXT, _f_mono(10))
        setattr(self, key, f)
        return f

    @Slot(object)
    def _append_chat_msg(self, msg: dict) -> None:
        kind = msg.get('kind', 'chat')
        who = msg.get('operator', '?')
        ts_raw = msg.get('ts', time.time())
        ts = time.strftime('%H:%M', time.localtime(ts_raw))

        last_who = self._chat_last_who
        last_ts = self._chat_last_ts
        grouped = (kind == 'chat'
                   and last_who == who
                   and (ts_raw - last_ts) < 60)

        if kind == 'day':
            label = msg.get('text', '')
            self._chat_insert(
                f"\n  ── {label} {'─' * 30}\n\n", 'day')

        elif kind == 'system':
            self._chat_insert(
                f"{ts}  {msg.get('text','')}\n", 'system')

        elif kind == 'notice':
            self._chat_insert(
                f"{ts}  {who} {msg.get('text','')}\n", 'system')

        elif kind == 'dm':
            recipient = msg.get('recipient', '?')
            sender = msg.get('operator', '?')
            text = msg.get('text', '')
            if sender == self.client.name:
                tag = f"dm → {recipient}"
            else:
                tag = f"dm ← {sender}"
            self._chat_insert(f"\n{ts}  ", 'meta')
            self._chat_insert(f"[{tag}]\n", 'dm')
            self._chat_insert(f"     {text}\n", 'body')
            last_who, last_ts = None, 0

        elif kind == 'action':
            self._chat_insert(f"\n{ts}  * ", 'meta')
            self._chat_insert(who, f'spk_{who}')
            self._chat_insert(f"  {msg.get('text', '')}\n", 'body')
            last_who, last_ts = None, 0

        elif kind == 'file':
            name = msg.get('text', 'file')
            size = int(msg.get('file_size', 0) or 0)
            digest = msg.get('file_hash', '') or ''
            self._chat_insert(f"\n{ts}  ", 'meta')
            self._chat_insert(who, f'spk_{who}')
            self._chat_insert('  📎 ', 'meta')
            self._chat_insert(name, 'body')
            self._chat_insert(f"  ({_human_bytes(size)})\n", 'meta')
            if digest:
                self._chat_insert(f"     sha256:{digest}\n", 'meta')
            last_who, last_ts = None, 0

        else:
            text = msg.get('text', '')
            if grouped:
                self._chat_insert("          ", 'meta')
            else:
                self._chat_insert(f"\n{ts}  ", 'meta')
                self._chat_insert(who, f'spk_{who}')
                self._chat_insert('  ', 'meta')

            me = self.client.name
            if me and ('@' + me) in text:
                before, rest = text.split('@' + me, 1)
                self._chat_insert(before, 'body')
                self._chat_insert('@' + me, 'mention')
                self._chat_insert(rest + '\n', 'body')
            else:
                self._chat_insert(text + '\n', 'body')
            last_who, last_ts = who, ts_raw

        self._chat_last_who = last_who
        self._chat_last_ts = last_ts

        self.chat_widget.ensureCursorVisible()

    @Slot(str)
    def _append_chat_raw(self, line: str) -> None:
        if self._shutdown.is_set():
            return
        line = _strip_ansi(line)
        try:
            cur = self.chat_widget.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            cur.insertText(line + '\n', self._chat_fmt('body'))
            self.chat_widget.setTextCursor(cur)
            self.chat_widget.ensureCursorVisible()
        except Exception:
            pass

    @Slot(object)
    def _update_chat_topic(self, topic: dict) -> None:
        text = topic.get('text', '')
        if not text:
            self.chat_topic.setVisible(False)
            return
        set_by = topic.get('set_by', '?')
        self.chat_topic_lbl.setText(f"\U0001F4CC  {text}   ·  {set_by}")
        self.chat_topic.setVisible(True)

    # ==================================================================
    # Misc

    def _about(self) -> None:
        QMessageBox.information(
            self, 'About TornadoC2',
            'TornadoC2 operator console\n\n'
            'The CLI is the backend. Every command here goes '
            'through the same Client methods the terminal client '
            'uses. Type `help` for the command index.')

    # Override so `_chat_insert` can dispatch dynamic speaker tags
    def _chat_insert(self, text: str, tag: str) -> None:
        cur = self.chat_widget.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        if tag.startswith('spk_'):
            fmt = self._chat_speaker_fmt(tag[4:])
        else:
            fmt = self._chat_fmt(tag)
        cur.insertText(text, fmt)
        self.chat_widget.setTextCursor(cur)


# ---------------------------------------------------------------------
# Entry point

def main_gui(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog='beacon-client --gui',
        description='TornadoC2 operator client — GUI mode')
    ap.add_argument('-c', '--config', required=True,
                    help='Path to operator config file')
    ap.add_argument('--gui', action='store_true',
                    help='(implicit) launch the PySide6 GUI')
    ap.add_argument('--debug', action='store_true',
                    help='print full tracebacks')
    args = ap.parse_args(argv)

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName('TornadoC2')
    try:
        app.setStyle('Fusion')
    except Exception:
        pass

    try:
        platform = app.platformName()
        if platform:
            print(f"  Qt platform: {platform}", file=sys.stderr)
    except Exception:
        pass

    _resolve_fonts()
    app.setFont(_UI_FONT)
    app.setStyleSheet(STYLESHEET.replace(
        '__UI_FONT__', _FONTS.get('ui', 'sans-serif')
    ).replace('__MONO_FONT__', _FONTS.get('mono', 'monospace')))

    from tornado_client import config as cfg_mod
    from tornado_client.transport import Transport

    try:
        cfg = cfg_mod.load(args.config)
    except (OSError, ValueError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1

    age = cfg_mod.age_days(args.config)
    if age > 90:
        print(f"warning: config is {age:.0f} days old",
              file=sys.stderr)

    saved_getpass = _getpass_mod.getpass
    try:
        _getpass_mod.getpass = _early_getpass
        try:
            tp = Transport(cfg)
        except Exception as exc:
            if args.debug:
                raise
            print(f"could not set up the TLS transport: {exc}",
                  file=sys.stderr)
            print("the config's ca_pem / client_cert / client_key "
                  "are probably malformed — regenerate the config "
                  "on the server with `operators export`.",
                  file=sys.stderr)
            return 1
    finally:
        _getpass_mod.getpass = saved_getpass

    try:
        window = GuiApp(cfg, tp, debug=args.debug,
                        config_path=args.config)
    except Exception as exc:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        if args.debug:
            raise
        print(f"GUI startup failed: {exc}", file=sys.stderr)
        return 1

    window.show()

    try:
        return app.exec()
    finally:
        try:
            tp.close()
        except Exception:
            pass


if __name__ == '__main__':
    sys.exit(main_gui())