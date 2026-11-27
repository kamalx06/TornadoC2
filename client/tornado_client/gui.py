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
import asyncio
import queue
import re
import secrets as _secrets
import sys
import threading
import time
from collections import deque
from typing import Optional

# ── Platform selection ────────────────────────────────────────
if os.environ.get('WAYLAND_DISPLAY'):
    os.environ.setdefault('QT_QPA_PLATFORM', 'wayland;xcb')
elif os.environ.get('DISPLAY'):
    os.environ.setdefault('QT_QPA_PLATFORM', 'xcb')

# ── GL backend selection ──────────────────────────────────────
os.environ.setdefault('LIBGL_ALWAYS_SOFTWARE', '1')

from PySide6.QtCore import (
    QAbstractTableModel, QEvent, QPoint, Qt, QTimer, Signal, Slot,
)
from PySide6.QtGui import (
    QAction, QBrush, QColor, QFont, QFontDatabase, QIntValidator, QPainterPath, QPen,
    QKeySequence, QPainter, QShortcut, QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QFrame, QGraphicsPathItem, QGraphicsRectItem, QGraphicsScene, QGraphicsTextItem,
    QGraphicsView, QGridLayout, QGroupBox, QHBoxLayout, QInputDialog,
    QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QKeySequenceEdit,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea,
    QSplitter, QStatusBar, QTableView, QTabWidget,
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
    PRIV_ROOT     = '#ffd166'
    PRIV_ADMIN    = '#ff8c42'
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
QWidget#headerBar {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {Palette.HEADER_BG}, stop:1 {Palette.BG_SOFT});
    border-bottom: 1px solid {Palette.BORDER};
}}
QFrame#connChip {{
    background: {Palette.BG_APP};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 11px;
}}
QGraphicsView#graphView {{
    background: {Palette.BG_APP};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 8px;
}}
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
    font-size: 15pt;
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
QPushButton#danger {{
    color: {Palette.ERR};
    border-color: {Palette.ERR_BORDER};
    background: {Palette.ERR_BG};
}}
QPushButton#danger:hover {{ background: {Palette.ERR_BORDER}; }}
QFrame#detailCard {{
    background: {Palette.BG_PANEL};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 8px;
}}
QLabel#toolbarTitle {{ font-weight: 700; font-size: 12pt; }}
QLabel#countBadge {{
    color: {Palette.TEXT_MUTED};
    background: {Palette.BG_SOFT};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 9px;
    padding: 1px 8px;
    font-size: 8.5pt;
}}
QLabel#statusPill {{
    border-radius: 9px;
    padding: 2px 9px;
    font-size: 8.5pt;
    font-weight: 700;
    background: {Palette.BG_SOFT};
    color: {Palette.TEXT_MUTED};
}}
QLabel#statusPill[state="running"] {{
    color: {Palette.OK}; background: {Palette.OK_BG};
    border: 1px solid {Palette.OK_BORDER};
}}
QLabel#statusPill[state="error"] {{
    color: {Palette.ERR}; background: {Palette.ERR_BG};
    border: 1px solid {Palette.ERR_BORDER};
}}
QLabel#statusPill[state="stopped"] {{
    color: {Palette.TEXT_MUTED}; border: 1px solid {Palette.BORDER};
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
    background: {Palette.ACCENT_SOFT};
    color: {Palette.TEXT};
    border-left: 2px solid {Palette.ACCENT};
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
    border-top: 1px solid {Palette.BORDER_SOFT};
    background: {Palette.BG_PANEL};
    top: -1px;
}}
QTabWidget::tab-bar {{ left: 0px; }}
QTabBar {{ qproperty-drawBase: 0; }}
QTabBar::tab {{
    background: transparent;
    color: {Palette.TEXT_MUTED};
    padding: 10px 18px;
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
QLabel#statusMeta {{
    color: {Palette.TEXT_FAINT};
    font-family: "__MONO_FONT__";
    font-size: 8.5pt;
    padding: 0 10px;
    border-left: 1px solid {Palette.BORDER_SOFT};
}}

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
QFrame#dlgHeader {{
    background: {Palette.BG_APP};
    border-bottom: 1px solid {Palette.BORDER};
}}
QFrame#dlgFooter {{
    background: {Palette.BG_APP};
    border-top: 1px solid {Palette.BORDER};
}}
QLabel#typeBadge {{
    color: {Palette.ACCENT_HI};
    background: {Palette.ACCENT_SOFT};
    border: 1px solid {Palette.ACCENT_FAINT};
    border-radius: 9px;
    padding: 2px 9px;
    font-size: 8.5pt;
    font-weight: 700;
}}
QLabel#callout {{
    color: {Palette.WARN};
    background: {Palette.WARN_BG};
    border: 1px solid {Palette.WARN_BORDER};
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 9pt;
}}
QLabel#errorText {{
    color: {Palette.ERR};
    background: {Palette.ERR_BG};
    border: 1px solid {Palette.ERR_BORDER};
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 9pt;
}}
QGroupBox {{
    background: {Palette.BG_PANEL};
    border: 1px solid {Palette.BORDER_SOFT};
    border-radius: 8px;
    margin-top: 16px;
    padding: 16px 12px 12px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: {Palette.TEXT_MUTED};
    font-weight: 700;
    font-size: 8.5pt;
    text-transform: uppercase;
    letter-spacing: 0.7px;
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




class BeaconModel(QAbstractTableModel):
    """Virtual beacon table.

    Only the filtered/sorted rows live here; the view paints what
    is visible. This is what keeps 10k rows scrollable without
    rebuilding item widgets on every refresh.
    """

    HEADERS = ('BEACON', 'USER@HOST', 'PRIV', 'OS', 'LAST', 'VIEW')

    def __init__(self) -> None:
        super().__init__()
        self._rows: list = []
        self._ids: list = []

    def rowCount(self, parent=None) -> int:
        return 0 if parent and parent.isValid() else len(self._rows)

    def columnCount(self, parent=None) -> int:
        return 0 if parent and parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=None):
        if orientation == Qt.Orientation.Horizontal and \
                role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index, role=None):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return row['cells'][col]
        if role == Qt.ItemDataRole.UserRole:
            return row['id']
        if role == Qt.ItemDataRole.ToolTipRole:
            return row['tip']
        if role == Qt.ItemDataRole.ForegroundRole:
            return QBrush(QColor(row['colors'][col]))
        if role == Qt.ItemDataRole.BackgroundRole and row['tint']:
            return QBrush(QColor(row['tint']))
        return None

    def set_view(self, rows) -> None:
        self.beginResetModel()
        self._rows = rows
        self._ids = [r['id'] for r in rows]
        self.endResetModel()

    def id_at(self, row: int) -> str:
        if 0 <= row < len(self._ids):
            return str(self._ids[row])
        return ''

    def row_of(self, beacon_id: str) -> int:
        try:
            return self._ids.index(int(beacon_id))
        except (ValueError, TypeError):
            return -1


class _BeaconView(QTableView):
    """QTableView with the empty-state hint painted in the viewport."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._empty_text = ''

    def set_empty_text(self, text: str) -> None:
        if text != self._empty_text:
            self._empty_text = text
            self.viewport().update()

    def paintEvent(self, ev) -> None:
        super().paintEvent(ev)
        if (self.model() is not None and self.model().rowCount()) or \
                not self._empty_text:
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
            'wasm_extensions': False,
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
        if v.get('wasm_extensions') and v['fmt'] != 'stager':
            tail_parts.append('wasm')
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
                'wasm_extensions',
                'WASM extension host (+~1 MB)'))
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
        take('wasm_extensions',        'wasm_extensions', cast=bool)
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
        if v.get('wasm_extensions') and v['fmt'] != 'stager':
            p['wasm_extensions'] = True
        if v['verbose']:
            p['verbose'] = True

        self.result = p
        self.accept()


# ---------------------------------------------------------------------
# Main application

class _JumpDialog(QDialog):
    """Lateral movement dialog for the attached Windows beacon."""

    def __init__(self, parent, listeners):
        super().__init__(parent)
        self.setWindowTitle('Jump')
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        lay.addLayout(form)
        self.method = QComboBox()
        self.method.addItems(['psexec', 'winrm', 'wmi', 'scshell'])
        form.addRow('Method', self.method)
        self.target = QLineEdit()
        self.target.setPlaceholderText('host or IP')
        form.addRow('Target', self.target)
        self.listener = QComboBox()
        for lst in listeners:
            self.listener.addItem(
                f"{lst.get('name')} ({lst.get('host')}:{lst.get('port')})",
                lst.get('id'))
        form.addRow('Listener', self.listener)
        self.user = QLineEdit()
        self.user.setPlaceholderText(r'DOMAIN\user (blank = current token)')
        form.addRow('User', self.user)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow('Password', self.password)
        self.service = QLineEdit()
        self.service.setPlaceholderText('tornadojump')
        form.addRow('Service', self.service)
        self.port = QLineEdit('5986')
        form.addRow('WinRM port', self.port)
        self.cleanup = QCheckBox('Clean up service and payload')
        self.cleanup.setChecked(True)
        form.addRow('', self.cleanup)
        self.error = QLabel('')
        self.error.setObjectName('errorText')
        self.error.setWordWrap(True)
        self.error.setVisible(False)
        lay.addWidget(self.error)
        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _ok(self):
        if not self.target.text().strip():
            self.error.setText('Target is required')
            self.error.setVisible(True)
            return
        self.accept()

    def parts(self):
        p = ['jump', self.method.currentText(),
             self.target.text().strip()]
        if self.listener.currentData():
            p += ['--listener', self.listener.currentData()]
        if self.user.text().strip():
            p += ['--user', self.user.text().strip(),
                  '--pass', self.password.text()]
        if self.service.text().strip():
            p += ['--service', self.service.text().strip()]
        if self.method.currentText() == 'winrm':
            p += ['--port', self.port.text().strip() or '5986']
        if not self.cleanup.isChecked():
            p.append('--no-cleanup')
        return p


_PALETTE_RECENTS: deque = deque(maxlen=8)

KEY_DEFAULTS = {
    'quit': 'Ctrl+Q', 'clear_log': 'Ctrl+L', 'build': 'Ctrl+B',
    'chat': 'Ctrl+T', 'tab_log': 'Ctrl+1', 'tab_chat': 'Ctrl+2',
    'tab_graph': 'Ctrl+3', 'tab_listeners': 'Ctrl+4',
    'refresh': 'F5', 'palette': 'Ctrl+K', 'spawnto': 'Ctrl+Shift+W',
}


class _CommandPalette(QDialog):
    """Fuzzy command / target picker (Ctrl+K)."""

    def __init__(self, parent, entries) -> None:
        super().__init__(parent)
        self.setWindowTitle('Command palette')
        self.setMinimumSize(560, 420)
        self.line = ''
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText(
            'type a command or target…  (Enter runs)')
        self.search.textChanged.connect(self._filter)
        lay.addWidget(self.search)
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(self._accept)
        lay.addWidget(self.list, 1)
        self.search.returnPressed.connect(self._accept)
        self._entries = entries
        self._filter('')
        self.search.setFocus()

    @staticmethod
    def _score(term: str, hay: str) -> int:
        """Lower is better; -1 means no match."""
        if not term:
            return 0
        if hay.startswith(term):
            return 0
        i = hay.find(' ' + term)
        if i >= 0:
            return 1
        i = hay.find(term)
        if i >= 0:
            return 2
        pos = 0
        for ch in term:
            pos = hay.find(ch, pos)
            if pos < 0:
                return -1
            pos += 1
        return 3

    def _filter(self, text) -> None:
        low = text.strip().lower()
        self.list.clear()
        scored = []
        for line, label in self._entries:
            hay = (line + ' ' + label).lower()
            score = self._score(low, hay)
            if score < 0:
                continue
            recent = line in _PALETTE_RECENTS
            if recent:
                score -= 1
            scored.append((score, len(hay), line, label))
        scored.sort(key=lambda x: (x[0], x[1], x[2]))
        for _score, _len, line, label in scored[:200]:
            it = QListWidgetItem(label)
            it.setData(Qt.ItemDataRole.UserRole, line)
            self.list.addItem(it)
        if self.list.count():
            self.list.setCurrentRow(0)

    def _accept(self) -> None:
        it = self.list.currentItem()
        if it is None:
            return
        self.line = it.data(Qt.ItemDataRole.UserRole)
        if self.line in _PALETTE_RECENTS:
            _PALETTE_RECENTS.remove(self.line)
        _PALETTE_RECENTS.appendleft(self.line)
        self.accept()


class _AiPanel(QWidget):
    """Resident AI console tab.

    Owns a private asyncio loop thread so a turn never occupies
    the beacon command worker. Prompts and T3 approvals use the
    GUI's modal input interception.
    """

    sig_text = Signal(str)
    sig_done = Signal(object)

    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.client = app.client
        self._transcript: list = []
        self._busy = False
        self._future = None
        from concurrent.futures.thread import (
            ThreadPoolExecutor as _TPE,
        )
        # Python 3.15 lazy imports can leave asyncio's module-level
        # ``concurrent.futures.ThreadPoolExecutor`` as a non-type
        # proxy under Qt. Pin the real class before the loop runs.
        import asyncio.base_events as _be
        _be.concurrent.futures.ThreadPoolExecutor = _TPE
        self._loop = asyncio.new_event_loop()
        self._setting_executor = _TPE(
            max_workers=4, thread_name_prefix='ai-http')
        self._loop.set_default_executor(self._setting_executor)
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name='gui-ai-loop', daemon=True)
        self._thread.start()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(Sp.M, Sp.M, Sp.M, Sp.M)
        lay.setSpacing(Sp.S)

        top = QHBoxLayout()
        title = QLabel('AI console')
        title.setObjectName('toolbarTitle')
        top.addWidget(title)
        self.provider_lbl = QLabel('not configured')
        self.provider_lbl.setObjectName('dlgSub')
        top.addWidget(self.provider_lbl)
        top.addStretch(1)
        self.settings_btn = QPushButton('Settings')
        self.settings_btn.setObjectName('ghost')
        self.settings_btn.clicked.connect(app._open_ai_settings)
        top.addWidget(self.settings_btn)
        self.reset_btn = QPushButton('Reset')
        self.reset_btn.setObjectName('ghost')
        self.reset_btn.clicked.connect(self._reset)
        top.addWidget(self.reset_btn)
        self.stop_btn = QPushButton('Stop')
        self.stop_btn.setObjectName('danger')
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        top.addWidget(self.stop_btn)
        lay.addLayout(top)

        self.view = QPlainTextEdit()
        self.view.setObjectName('logView')
        self.view.setReadOnly(True)
        self.view.setFont(_f_mono(10))
        self.view.setMaximumBlockCount(20000)
        lay.addWidget(self.view, 1)

        self.status = QLabel(
            'Ask a question. T3 tools still ask for approval.')
        self.status.setObjectName('dlgSub')
        lay.addWidget(self.status)

        row = QHBoxLayout()
        self.entry = QLineEdit()
        self.entry.setPlaceholderText(
            'Ask the model…  (Enter sends, /settings, /reset)')
        self.entry.returnPressed.connect(self._send)
        row.addWidget(self.entry, 1)
        self.send_btn = QPushButton('Send')
        self.send_btn.setObjectName('primary')
        self.send_btn.clicked.connect(self._send)
        row.addWidget(self.send_btn)
        lay.addLayout(row)

        self.sig_text.connect(self._append)
        self.sig_done.connect(self._done)

    def _append(self, text: str) -> None:
        if text == '':
            self.view.appendPlainText('')
        else:
            self.view.appendPlainText(text)

    def _load_cfg(self):
        from tornadoc2_mcp.config import (
            DEFAULT_AI_PATH, load_ai_config,
        )
        return load_ai_config(DEFAULT_AI_PATH,
                              require_provider=True)

    def _reset(self) -> None:
        if self._busy:
            return
        self._transcript = []
        self.view.clear()
        self._append('[ai] transcript cleared')

    def _stop(self) -> None:
        if self._future is not None:
            self._future.cancel()
            self.status.setText('cancelling…')

    def _send(self) -> None:
        if self._busy:
            return
        text = self.entry.text().strip()
        if not text:
            return
        if text in ('/reset', 'reset'):
            self.entry.clear()
            return self._reset()
        if text in ('/settings', 'settings'):
            self.entry.clear()
            return self.app._open_ai_settings()
        try:
            cfg = self._load_cfg()
        except Exception as exc:
            self._append(f'[ai] {exc}')
            hint = getattr(exc, 'hint', '') or ''
            if hint:
                self._append(f'     {hint}')
            self.app._open_ai_settings()
            return
        self.provider_lbl.setText(f'{cfg.provider} / {cfg.model}')
        self.entry.clear()
        self._append(f'› {text}')
        self._busy = True
        self.send_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status.setText('thinking…')
        from tornadoc2_mcp.adapter import ClientAdapter
        from tornadoc2_mcp.console.loop import run_ai_turn
        adapter = ClientAdapter(self.client)
        self._future = asyncio.run_coroutine_threadsafe(
            run_ai_turn(cfg, adapter, self._transcript, text,
                        self.sig_text.emit),
            self._loop)
        self._future.add_done_callback(self.sig_done.emit)

    def _done(self, fut) -> None:
        self._busy = False
        self._future = None
        self.send_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        try:
            err = fut.result()
        except asyncio.CancelledError:
            err = 'cancelled'
        except Exception as exc:
            err = f'{type(exc).__name__}: {exc}'
        if err:
            self._append(f'[ai] {err}')
            self.status.setText(err)
        else:
            self.status.setText('done')


class _ListenerDialog(QDialog):
    """Protocol-aware create/edit dialog for one listener."""

    TYPES = ('http', 'quic', 'websocket', 'dns', 'icmp',
             'wireguard')

    def __init__(self, parent, certs: dict, profiles: list,
                 listener=None) -> None:
        super().__init__(parent)
        self._certs = certs or {}
        self._profiles = list(profiles or [])
        self._listener = listener
        self._last_type = (listener or {}).get('type', 'http')
        self._running = bool(
            listener and listener.get('status') == 'running')
        self.setWindowTitle(
            'Edit listener' if listener else 'Create listener')
        self.setMinimumWidth(520)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QFrame()
        header.setObjectName('dlgHeader')
        hl = QVBoxLayout(header)
        hl.setContentsMargins(22, 16, 22, 14)
        hl.setSpacing(4)
        title_row = QHBoxLayout()
        self.title = QLabel(
            'Edit listener' if listener else 'Create listener')
        self.title.setObjectName('dlgHeader')
        title_row.addWidget(self.title)
        self.badge = QLabel(
            (listener or {}).get('type', 'http').upper())
        self.badge.setObjectName('typeBadge')
        title_row.addWidget(self.badge)
        title_row.addStretch(1)
        hl.addLayout(title_row)
        self.subtitle = QLabel(
            'Configure the bind, TLS material and profile scope. '
            'The listener is persisted and survives restart.')
        self.subtitle.setObjectName('dlgSub')
        self.subtitle.setWordWrap(True)
        hl.addWidget(self.subtitle)
        outer.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(20, 14, 20, 14)
        bl.setSpacing(10)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        def _lab(text):
            lbl = QLabel(text)
            lbl.setStyleSheet(f'color: {Palette.TEXT_MUTED};')
            return lbl

        basics = QGroupBox('Basics')
        bg = QGridLayout(basics)
        bg.setHorizontalSpacing(12)
        bg.setVerticalSpacing(8)
        bg.setColumnStretch(1, 3)
        bg.setColumnStretch(3, 1)
        self.name_edit = QLineEdit((listener or {}).get('name', ''))
        self.name_edit.setPlaceholderText('primary')
        self.type_combo = QComboBox()
        self.type_combo.addItems(self.TYPES)
        if listener:
            self.type_combo.setCurrentText(listener.get('type', 'http'))
            self.type_combo.setEnabled(False)
        bg.addWidget(_lab('Name'), 0, 0)
        bg.addWidget(self.name_edit, 0, 1)
        bg.addWidget(_lab('Type'), 0, 2)
        bg.addWidget(self.type_combo, 0, 3)
        self.host_edit = QLineEdit(
            (listener or {}).get('host', '0.0.0.0'))
        self.host_edit.setPlaceholderText('0.0.0.0')
        self.port_edit = QLineEdit(
            str((listener or {}).get('port', 8881)))
        self.port_edit.setValidator(QIntValidator(0, 65535, self))
        self.port_edit.setMaximumWidth(110)
        self.port_label = _lab('Port')
        bg.addWidget(_lab('Bind host'), 1, 0)
        bg.addWidget(self.host_edit, 1, 1)
        bg.addWidget(self.port_label, 1, 2)
        bg.addWidget(self.port_edit, 1, 3)
        if self._running:
            self.host_edit.setEnabled(False)
            self.port_edit.setEnabled(False)
        bl.addWidget(basics)

        # ---- TLS (http / quic / websocket) ----
        self.tls_group = QGroupBox('TLS')
        tf = QGridLayout(self.tls_group)
        tf.setHorizontalSpacing(12)
        tf.setVerticalSpacing(8)
        tf.setColumnStretch(1, 1)
        tf.setColumnStretch(3, 1)
        self.tls_mode = QComboBox()
        mode = ((listener or {}).get('tls') or {}).get(
            'mode', 'server')
        if listener and listener.get('type') == 'websocket':
            self.tls_mode.addItems(['none', 'server'])
        else:
            self.tls_mode.addItems(['server', 'mtls'])
        self.tls_mode.setCurrentText(mode)
        tf.addWidget(_lab('Mode'), 0, 0)
        tf.addWidget(self.tls_mode, 0, 1, 1, 3)
        self.cert_combo = self._path_combo('certs')
        self.key_combo = self._path_combo('keys')
        self.ca_combo = self._path_combo('cas')
        self.cert_row = _lab('Cert path')
        self.key_row = _lab('Key path')
        self.ca_row = _lab('CA path')
        tf.addWidget(self.cert_row, 1, 0)
        tf.addWidget(self.cert_combo, 1, 1)
        tf.addWidget(self.key_row, 1, 2)
        tf.addWidget(self.key_combo, 1, 3)
        tf.addWidget(self.ca_row, 2, 0)
        tf.addWidget(self.ca_combo, 2, 1, 1, 3)
        tls = (listener or {}).get('tls') or {}
        if tls.get('cert_path'):
            self.cert_combo.setCurrentText(tls['cert_path'])
        if tls.get('key_path'):
            self.key_combo.setCurrentText(tls['key_path'])
        if tls.get('ca_path'):
            self.ca_combo.setCurrentText(tls['ca_path'])
        self.tls_mode.currentTextChanged.connect(
            self._on_tls_mode)
        bl.addWidget(self.tls_group)

        # ---- Profiles (multi) ----
        self.profiles_group = QGroupBox('Profiles')
        pf = QVBoxLayout(self.profiles_group)
        self.profile_list = QListWidget()
        self.profile_list.setSelectionMode(
            QListWidget.SelectionMode.ExtendedSelection)
        self.profile_list.setMinimumHeight(110)
        for p in self._profiles:
            name = p.get('name') if isinstance(p, dict) else p
            if name:
                QListWidgetItem(name, self.profile_list)
        wanted = set((listener or {}).get('profiles') or [])
        for i in range(self.profile_list.count()):
            it = self.profile_list.item(i)
            if it.text() in wanted:
                it.setSelected(True)
        hint = QLabel('Blank selection serves every profile.')
        hint.setObjectName('formHint')
        pf.addWidget(hint)
        pf.addWidget(self.profile_list)
        bl.addWidget(self.profiles_group)

        # ---- DNS ----
        self.dns_group = QGroupBox('Zone')
        df = QGridLayout(self.dns_group)
        df.setColumnStretch(1, 1)
        self.domain_edit = QLineEdit(
            (listener or {}).get('domain', ''))
        self.domain_edit.setPlaceholderText('c2.example.com')
        self.dns_profile = QComboBox()
        self.dns_profile.setEditable(True)
        self._fill_profile_combo(self.dns_profile, wanted, dns_only=True)
        df.addWidget(_lab('Zone'), 0, 0)
        df.addWidget(self.domain_edit, 0, 1)
        df.addWidget(_lab('Profile'), 1, 0)
        df.addWidget(self.dns_profile, 1, 1)
        bl.addWidget(self.dns_group)

        # ---- ICMP ----
        self.icmp_group = QGroupBox('ICMP')
        inf = QGridLayout(self.icmp_group)
        inf.setColumnStretch(1, 1)
        self.public_edit = QLineEdit(
            (listener or {}).get('public_host', ''))
        self.public_edit.setPlaceholderText('203.0.113.5')
        self.icmp_profile = QComboBox()
        self.icmp_profile.setEditable(True)
        self._fill_profile_combo(self.icmp_profile, wanted, dns_only=True)
        inf.addWidget(_lab('Public IPv4'), 0, 0)
        inf.addWidget(self.public_edit, 0, 1)
        inf.addWidget(_lab('Profile'), 1, 0)
        inf.addWidget(self.icmp_profile, 1, 1)
        warn = QLabel('Raw-socket listener: requires CAP_NET_RAW '
                      'on the team-server host.')
        warn.setObjectName('callout')
        warn.setWordWrap(True)
        inf.addWidget(warn, 2, 0, 1, 2)
        bl.addWidget(self.icmp_group)

        # ---- WireGuard ----
        self.wg_group = QGroupBox('WireGuard')
        wf = QGridLayout(self.wg_group)
        wf.setHorizontalSpacing(12)
        wf.setColumnStretch(1, 1)
        wf.setColumnStretch(3, 1)
        self.subnet_edit = QLineEdit(
            (listener or {}).get('subnet', '10.99.0.0/24'))
        self.server_ip_edit = QLineEdit(
            (listener or {}).get('server_tunnel_ip', '10.99.0.1'))
        self.iface_edit = QLineEdit(
            (listener or {}).get('interface', ''))
        self.iface_edit.setPlaceholderText('auto')
        wf.addWidget(_lab('Subnet'), 0, 0)
        wf.addWidget(self.subnet_edit, 0, 1)
        wf.addWidget(_lab('Server tunnel IP'), 0, 2)
        wf.addWidget(self.server_ip_edit, 0, 3)
        wf.addWidget(_lab('Interface'), 1, 0)
        wf.addWidget(self.iface_edit, 1, 1, 1, 3)
        wwarn = QLabel(
            'Kernel WireGuard: requires CAP_NET_ADMIN and the '
            'wireguard module. A stale interface is swept on start.')
        wwarn.setObjectName('callout')
        wwarn.setWordWrap(True)
        wf.addWidget(wwarn, 2, 0, 1, 4)
        bl.addWidget(self.wg_group)

        self.enabled_box = QCheckBox('Enabled on next boot')
        self.enabled_box.setChecked(
            bool((listener or {}).get('enabled', True)))
        bl.addWidget(self.enabled_box)

        self.summary = QLabel('')
        self.summary.setObjectName('summaryStrip')
        bl.addWidget(self.summary)

        self.error = QLabel('')
        self.error.setObjectName('errorText')
        self.error.setWordWrap(True)
        self.error.setVisible(False)
        bl.addWidget(self.error)

        footer = QFrame()
        footer.setObjectName('dlgFooter')
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(20, 12, 20, 12)
        fl.addStretch(1)
        cancel = QPushButton('Cancel')
        cancel.setObjectName('ghost')
        cancel.clicked.connect(self.reject)
        fl.addWidget(cancel)
        self.save_btn = QPushButton(
            'Save changes' if listener else 'Create listener')
        self.save_btn.setObjectName('primary')
        self.save_btn.clicked.connect(self._ok)
        fl.addWidget(self.save_btn)
        outer.addWidget(footer)

        self.type_combo.currentTextChanged.connect(self._on_type)
        self.tls_mode.currentTextChanged.connect(
            self._on_tls_mode)
        for w in (self.host_edit, self.port_edit, self.public_edit):
            w.textChanged.connect(self._update_summary)
        self._on_type(self.type_combo.currentText())
        self._on_tls_mode(self.tls_mode.currentText())

    def _path_combo(self, bucket):
        combo = QComboBox()
        combo.setEditable(True)
        for path in self._certs.get(bucket) or []:
            combo.addItem(path)
        if combo.count() == 0:
            combo.setCurrentText({
                'certs': 'tls_certs/server.pem',
                'keys': 'tls_certs/server.key',
                'cas': 'mtls_certs/ca.pem',
            }.get(bucket, ''))
        return combo

    def _fill_profile_combo(self, combo, wanted, dns_only=False):
        for p in self._profiles:
            if dns_only and isinstance(p, dict) \
                    and not p.get('has_dns_label'):
                continue
            name = p.get('name') if isinstance(p, dict) else p
            if name:
                combo.addItem(name)
        for w in wanted:
            combo.setCurrentText(w)

    def _on_type(self, ltype) -> None:
        defaults = {
            'http': '8881', 'quic': '8883',
            'websocket': '8884', 'dns': '53', 'wireguard': '51820',
        }
        current = self.port_edit.text().strip()
        old_default = defaults.get(self._last_type)
        if not current or current == old_default:
            if ltype in defaults:
                self.port_edit.setText(defaults[ltype])
        self._last_type = ltype
        self.save_btn.setText(
            'Save changes' if self._listener else
            f'Create {ltype} listener')
        self.tls_group.setVisible(
            ltype in ('http', 'quic', 'websocket'))
        self.profiles_group.setVisible(
            ltype in ('http', 'quic', 'websocket'))
        self.dns_group.setVisible(ltype == 'dns')
        self.icmp_group.setVisible(ltype == 'icmp')
        self.wg_group.setVisible(ltype == 'wireguard')
        icmp = ltype == 'icmp'
        self.port_edit.setVisible(not icmp)
        self.port_label.setVisible(not icmp)
        self.badge.setText(ltype.upper())
        subtitles = {
            'http': 'HTTPS/JSON listener. TLS material is required '
                    'unless mode is none.',
            'quic': 'HTTP/3 over UDP. Same JSON protocol as HTTP; '
                    'reaches networks that permit UDP.',
            'websocket': 'wss:// listener. Cert and key required; '
                         'client-cert attribution is not available.',
            'dns': 'UDP+TXT and TCP listener. The zone must be '
                   'delegated to this host.',
            'icmp': 'Raw ICMP echo listener. Linux, CAP_NET_RAW.',
            'wireguard': 'Kernel WireGuard UDP listener. Needs '
                         'CAP_NET_ADMIN and the kernel module.',
        }
        self.subtitle.setText(subtitles.get(ltype, ''))
        self._update_summary()
        if ltype == 'websocket' and self.tls_mode.count() == 2 \
                and self.tls_mode.itemText(0) == 'server':
            self.tls_mode.clear()
            self.tls_mode.addItems(['server', 'none'])
        elif ltype in ('http', 'quic') \
                and self.tls_mode.count() == 2 \
                and self.tls_mode.itemText(0) == 'none':
            self.tls_mode.clear()
            self.tls_mode.addItems(['server', 'mtls'])
        self._on_tls_mode(self.tls_mode.currentText())

    def _on_tls_mode(self, mode) -> None:
        on = mode != 'none'
        self.cert_combo.setVisible(on)
        self.cert_row.setVisible(on)
        self.key_combo.setVisible(on)
        self.key_row.setVisible(on)
        ca = on and mode == 'mtls'
        self.ca_combo.setVisible(ca)
        self.ca_row.setVisible(ca)

    def _fail(self, text) -> None:
        self.error.setText(text)
        self.error.setVisible(True)

    def _update_summary(self) -> None:
        host = self.host_edit.text().strip() or '0.0.0.0'
        ltype = self.type_combo.currentText()
        if ltype == 'icmp':
            target = self.public_edit.text().strip() or 'no IPv4 yet'
            self.summary.setText(f'icmp  ·  {target}')
        else:
            self.summary.setText(
                f'{ltype}  ·  {host}:{self.port_edit.text().strip()}')

    def _ok(self) -> None:
        self.error.setVisible(False)
        if not self.name_edit.text().strip():
            self._fail('A name is required.')
            return
        if self.spec() is None:
            return
        self.accept()

    def spec(self):
        ltype = self.type_combo.currentText()
        spec = {
            'type': ltype,
            'name': self.name_edit.text().strip(),
            'host': self.host_edit.text().strip() or '0.0.0.0',
            'enabled': self.enabled_box.isChecked(),
        }
        if ltype == 'icmp':
            spec['port'] = 0
            pub = self.public_edit.text().strip()
            if not pub:
                self._fail('A public IPv4 is required for ICMP.')
                return None
            spec['public_host'] = pub
            prof = self.icmp_profile.currentText().strip()
            if prof:
                spec['profiles'] = [prof]
        else:
            try:
                spec['port'] = int(self.port_edit.text().strip())
            except ValueError:
                self._fail('Port must be a number.')
                return None
        if ltype in ('http', 'quic', 'websocket'):
            mode = self.tls_mode.currentText()
            tls = {'mode': mode}
            if mode != 'none':
                cert = self.cert_combo.currentText().strip()
                key = self.key_combo.currentText().strip()
                if not cert or not key:
                    self._fail('Cert and key are required for TLS.')
                    return None
                tls['cert_path'] = cert
                tls['key_path'] = key
                if mode == 'mtls':
                    ca = self.ca_combo.currentText().strip()
                    if not ca:
                        self._fail('A CA is required for mTLS.')
                        return None
                    tls['ca_path'] = ca
            spec['tls'] = tls
            chosen = [it.text()
                      for it in self.profile_list.selectedItems()]
            if chosen:
                spec['profiles'] = chosen
        elif ltype == 'dns':
            zone = self.domain_edit.text().strip()
            if not zone:
                self._fail('A DNS zone is required.')
                return None
            spec['domain'] = zone
            prof = self.dns_profile.currentText().strip()
            if prof:
                spec['profiles'] = [prof]
        elif ltype == 'wireguard':
            spec['subnet'] = self.subnet_edit.text().strip()
            spec['server_tunnel_ip'] = (
                self.server_ip_edit.text().strip() or '10.99.0.1')
            if self.iface_edit.text().strip():
                spec['interface'] = self.iface_edit.text().strip()
        return spec


class _AiSettingsDialog(QDialog):
    """GUI editor for client/.tornadoc2/ai.json.

    No JSON typing. Provider/model/key, tuning, allowlists as
    checkboxes, listener gates as checkboxes. The API key is
    masked until revealed.
    """

    def __init__(self, parent, cfg, verbs, bofs) -> None:
        super().__init__(parent)
        from tornadoc2_mcp.config import KEYLESS_PROVIDERS, _VALID_PROVIDERS
        from tornadoc2_mcp.provider_defaults import default_base_url
        self._cfg = cfg
        self._default_base = default_base_url
        self._last_provider = cfg.provider
        self._KEYLESS = KEYLESS_PROVIDERS
        self.setWindowTitle('AI settings')
        self.setMinimumWidth(560)

        outer = QVBoxLayout(self)
        form = QFormLayout()
        outer.addLayout(form)

        self.provider = QComboBox()
        self.provider.addItems(list(_VALID_PROVIDERS))
        if cfg.provider:
            self.provider.setCurrentText(cfg.provider)
        form.addRow('Provider', self.provider)

        self.model = QLineEdit(cfg.model)
        form.addRow('Model', self.model)

        key_row = QHBoxLayout()
        self.api_key = QLineEdit(cfg.api_key)
        self.api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.reveal = QCheckBox('show')
        self.reveal.toggled.connect(
            lambda on: self.api_key.setEchoMode(
                QLineEdit.EchoMode.Normal if on
                else QLineEdit.EchoMode.Password))
        key_row.addWidget(self.api_key, 1)
        key_row.addWidget(self.reveal)
        kw = QWidget()
        kw.setLayout(key_row)
        form.addRow('API key', kw)

        self.base_url = QLineEdit(
            cfg.base_url or default_base_url(cfg.provider))
        self.base_url.setPlaceholderText('https://…')
        form.addRow('Base URL', self.base_url)
        self.temperature = QLineEdit(str(cfg.temperature))
        form.addRow('Temperature (0-2)', self.temperature)
        self.max_tokens = QLineEdit(str(cfg.max_tokens))
        form.addRow('Max tokens', self.max_tokens)
        self.max_context = QLineEdit(str(cfg.max_context_tokens))
        form.addRow('Max context tokens', self.max_context)
        self.max_turns = QLineEdit(str(cfg.max_turns))
        form.addRow('Max turns', self.max_turns)
        self.build_dir = QLineEdit(str(cfg.build_output_dir))
        form.addRow('Build output dir', self.build_dir)

        self.verbs = QListWidget()
        self._fill_checks(self.verbs, verbs, cfg.mcp_allow_verbs)
        form.addRow('Allow verbs', self.verbs)
        self.bofs = QListWidget()
        self._fill_checks(self.bofs, bofs, cfg.mcp_allow_bofs)
        form.addRow('Allow BOFs', self.bofs)

        self.allow_create = QCheckBox(
            'Allow MCP create_listener')
        self.allow_create.setChecked(cfg.mcp_allow_listener_create)
        self.allow_delete = QCheckBox(
            'Allow MCP delete_listener')
        self.allow_delete.setChecked(cfg.mcp_allow_listener_delete)
        form.addRow('MCP listeners', self.allow_create)
        form.addRow('', self.allow_delete)

        self.error = QLabel('')
        self.error.setWordWrap(True)
        self.error.setStyleSheet(f'color: {Palette.ERR};')
        outer.addWidget(self.error)

        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        outer.addWidget(bb)

        self.provider.currentTextChanged.connect(self._on_provider)
        self._on_provider(self.provider.currentText())

    @staticmethod
    def _fill_checks(widget, available, selected):
        chosen = set(selected or [])
        for name in list(dict.fromkeys(
                list(available) + list(chosen))):
            item = QListWidgetItem(name, widget)
            item.setFlags(item.flags()
                          | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(
                Qt.CheckState.Checked if name in chosen
                else Qt.CheckState.Unchecked)

    @staticmethod
    def _checked(widget):
        return [widget.item(i).text()
                for i in range(widget.count())
                if widget.item(i).checkState()
                == Qt.CheckState.Checked]

    def _on_provider(self, provider) -> None:
        keyless = provider in self._KEYLESS
        self.api_key.setEnabled(not keyless)
        if keyless and not self.api_key.text():
            self.api_key.setPlaceholderText('not required')
        current = self.base_url.text().strip()
        previous_default = self._default_base(self._last_provider)
        if not current or current == previous_default:
            self.base_url.setText(self._default_base(provider))
        self._last_provider = provider

    def _save(self) -> None:
        from tornadoc2_mcp.config import save_ai_config, DEFAULT_AI_PATH
        try:
            patch = {
                'provider': self.provider.currentText(),
                'model': self.model.text().strip(),
                'api_key': self.api_key.text().strip(),
                'base_url': self.base_url.text().strip(),
                'temperature': float(self.temperature.text()),
                'max_tokens': int(self.max_tokens.text()),
                'max_context_tokens': int(self.max_context.text()),
                'max_turns': int(self.max_turns.text()),
                'build_output_dir': self.build_dir.text().strip(),
                'mcp_allow_verbs': self._checked(self.verbs),
                'mcp_allow_bofs': self._checked(self.bofs),
                'mcp_allow_listener_create':
                    self.allow_create.isChecked(),
                'mcp_allow_listener_delete':
                    self.allow_delete.isChecked(),
            }
            save_ai_config(DEFAULT_AI_PATH, patch,
                           require_provider=True)
        except Exception as exc:
            hint = getattr(exc, 'hint', '') or ''
            self.error.setText(f'{exc}' + (f'\n{hint}' if hint else ''))
            return
        self.accept()


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
    sig_listeners       = Signal(object)
    sig_listener_certs  = Signal(object)
    sig_listener_profiles = Signal(object)
    sig_graph = Signal(object)
    sig_engagement = Signal(object)

    # ------------------------------------------------------------------

    def __init__(self, cfg, tp, debug: bool = False,
                 config_path: Optional[str] = None,
                 safe: bool = False) -> None:
        super().__init__()

        self.cfg = cfg
        self.tp = tp
        self.debug = debug
        self.config_path = config_path
        self.safe = safe
        self._keys: dict = dict(KEY_DEFAULTS)

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
        self._listener_rows: list = []
        self._listener_certs: Optional[dict] = None
        self._listener_profiles: Optional[list] = None
        self._listener_selected: Optional[str] = None

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
        self.sig_listeners.connect(self._apply_listener_rows)
        self.sig_listener_certs.connect(
            lambda c: setattr(self, '_listener_certs', c))
        self.sig_listener_profiles.connect(
            lambda p: setattr(self, '_listener_profiles', p))
        self.sig_graph.connect(self._apply_graph)
        self.sig_engagement.connect(self._apply_engagement)

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

        self._listener_timer = QTimer(self)
        self._listener_timer.timeout.connect(
            self._refresh_listeners_async)
        self._listener_timer.start(5000)

        self._restore_state()
        if self.safe:
            for t in (self._auto_timer, self._listener_timer,
                      self._graph_timer, self._eng_timer):
                t.stop()
            self._status('safe mode: background refresh off')

    # ==================================================================
    # Window state

    @staticmethod
    def _state_path():
        try:
            from tornadoc2_mcp import paths
            paths.ensure_state_dir()
            return paths.STATE_DIR / 'gui-state.json'
        except Exception:
            return None

    def _restore_state(self) -> None:
        if self.safe:
            return
        path = self._state_path()
        try:
            raw = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            return
        import base64
        try:
            if raw.get('geometry'):
                self.restoreGeometry(base64.b64decode(raw['geometry']))
            if isinstance(raw.get('split'), list):
                self._main_split.setSizes(raw['split'])
            if raw.get('tab') is not None:
                self.tabs.setCurrentIndex(int(raw['tab']))
            if raw.get('filter'):
                self.search_entry.setText(str(raw['filter']))
            for k, v in (raw.get('keys') or {}).items():
                if k in KEY_DEFAULTS and isinstance(v, str):
                    self._keys[k] = v
            self._light = bool(raw.get('light'))
            self._compact = bool(raw.get('compact'))
            if self._light or self._compact:
                self._apply_theme()
            self._bind_shortcuts()
        except Exception:
            pass

    def _save_state(self) -> None:
        path = self._state_path()
        if path is None:
            return
        import base64
        try:
            data = {
                'geometry': base64.b64encode(
                    bytes(self.saveGeometry())).decode('ascii'),
                'split': list(self._main_split.sizes()),
                'tab': self.tabs.currentIndex(),
                'filter': self.search_entry.text(),
                'light': bool(getattr(self, '_light', False)),
                'compact': bool(getattr(self, '_compact', False)),
                'keys': dict(self._keys),
            }
            tmp = path.with_suffix('.tmp')
            tmp.write_text(json.dumps(data), encoding='utf-8')
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except Exception:
            pass

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

        m_edit = mb.addMenu('&Edit')
        act = QAction('Keybindings…', self)
        act.setShortcut(QKeySequence('Ctrl+Alt+K'))
        act.triggered.connect(self._keymap_dialog)
        m_edit.addAction(act)
        m_edit.addSeparator()
        act = QAction('AI settings…', self)
        act.setShortcut(QKeySequence('Ctrl+,'))
        act.triggered.connect(self._open_ai_settings)
        m_edit.addAction(act)

        m_view = mb.addMenu('&View')
        act = QAction('Log tab', self)
        act.setShortcut(QKeySequence('Ctrl+1'))
        act.triggered.connect(lambda: self._select_tab(0))
        m_view.addAction(act)
        act = QAction('Chat tab', self)
        act.setShortcut(QKeySequence('Ctrl+2'))
        act.triggered.connect(lambda: self._select_tab(1))
        m_view.addAction(act)
        act = QAction('Graph tab', self)
        act.setShortcut(QKeySequence('Ctrl+3'))
        act.triggered.connect(lambda: self._select_tab(3))
        m_view.addAction(act)
        act = QAction('Listeners tab', self)
        act.setShortcut(QKeySequence('Ctrl+4'))
        act.triggered.connect(lambda: self._select_tab(2))
        m_view.addAction(act)
        act = QAction('Engagement tab', self)
        act.setShortcut(QKeySequence('Ctrl+5'))
        act.triggered.connect(lambda: self._select_tab(5))
        m_view.addAction(act)
        act = QAction('AI tab', self)
        act.setShortcut(QKeySequence('Ctrl+6'))
        act.triggered.connect(lambda: self._select_tab(4))
        m_view.addAction(act)
        m_view.addSeparator()
        m_view.addAction('Light theme', self._toggle_light)
        m_view.addAction('Compact density', self._toggle_compact)
        m_view.addSeparator()
        act = QAction('Clear log', self)
        act.setShortcut(QKeySequence('Ctrl+L'))
        act.triggered.connect(self._clear_log)
        m_view.addAction(act)
        m_view.addAction('Clear chat', self._clear_chat)

        m_tools = mb.addMenu('&Tools')
        act = QAction('Command palette…', self)
        act.setShortcut(QKeySequence('Ctrl+K'))
        act.triggered.connect(self._open_palette)
        m_tools.addAction(act)
        m_tools.addAction('Command index',
                          lambda: self._submit('help'))
        m_tools.addAction('List beacons',
                          lambda: self._submit('beacons'))
        m_tools.addAction('Audit log',
                          lambda: self._submit('audit 50'))
        m_tools.addAction('Engagement graph',
                          lambda: self._select_tab(3))
        m_tools.addAction('Jump…', self._open_jump)
        m_tools.addAction('Engagement', lambda: self._select_tab(5))
        m_tools.addSeparator()
        m_tools.addAction('Credential vault',
                          lambda: self._submit('creds list'))
        m_tools.addAction('Loot store',
                          lambda: self._submit('loot list'))
        m_tools.addAction('C2 profiles',
                          lambda: self._submit('c2-profiles'))
        act = QAction('AI console', self)
        act.setShortcut(QKeySequence('Ctrl+Shift+A'))
        act.triggered.connect(lambda: self._select_tab(4))
        m_tools.addAction(act)
        m_tools.addAction('AI settings…',
                          self._open_ai_settings)
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

    # ------------------------------------------------------------------
    # AI settings

    def _open_ai_settings(self) -> None:
        from tornadoc2_mcp.config import (
            DEFAULT_AI_PATH, ensure_ai_config, load_ai_config,
        )
        try:
            ensure_ai_config(DEFAULT_AI_PATH)
            cfg = load_ai_config(DEFAULT_AI_PATH)
        except Exception as exc:
            QMessageBox.warning(self, 'AI settings', str(exc))
            return
        verbs = []
        cat = self.client.commands or {}
        for row in (cat.get('main') or []) + (cat.get('beacon') or []):
            if isinstance(row, dict) and row.get('name'):
                verbs.append(row['name'])

        def work():
            bofs = []
            try:
                rows = self.client.tp.post('/api/v1/bofs', {}) or []
                bofs = [r.get('name') for r in rows if r.get('name')]
            except Exception:
                pass
            self.sig_post.emit(
                lambda: self._show_ai_settings(cfg, verbs, bofs))

        threading.Thread(target=work, daemon=True).start()

    def _open_jump(self) -> None:
        if not self.current_beacon:
            self._status('attach a Windows beacon first')
            return
        listeners = [lst for lst in getattr(self, 'listeners', [])
                     if lst.get('type') == 'http'
                     and lst.get('status') == 'running'
                     and (lst.get('tls') or {}).get('mode') != 'none']
        if not listeners:
            self._status('jump needs a running TLS HTTP listener')
            return
        dlg = _JumpDialog(self, listeners)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._submit(' '.join(dlg.parts()))

    def _open_palette(self) -> None:
        entries = []
        cat = self.client.commands or {}
        for row in (cat.get('main') or []):
            if not isinstance(row, dict) or not row.get('name'):
                continue
            name = row['name']
            entries.append((name,
                            f"{name}  —  {row.get('description','')}"))
        for b in self._beacon_rows[:200]:
            entries.append((f"use {b['id']}",
                            f"use #{b['id']}  {b.get('display_name','')}"))
        for n in ('beacons', 'listeners', 'graph', 'audit', 'chat',
                  'help', 'clear', 'ai'):
            if not any(e[0] == n for e in entries):
                entries.append((n, n))
        dlg = _CommandPalette(self, entries)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.line:
            self._submit(dlg.line)

    def _show_ai_settings(self, cfg, verbs, bofs) -> None:
        dlg = _AiSettingsDialog(self, cfg, verbs, bofs)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._status('AI settings saved')

    # ==================================================================
    # Central widget

    def _build_central(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_header())

        self.toasts = QWidget(root)
        self.toasts.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._toast_lay = QVBoxLayout(self.toasts)
        self._toast_lay.setContentsMargins(0, 8, 12, 0)
        self._toast_lay.setSpacing(6)
        self._toast_lay.addStretch(1)

        divider = QWidget()
        divider.setObjectName('headerDivider')
        divider.setFixedHeight(1)
        outer.addWidget(divider)

        self._main_split = splitter = QSplitter(Qt.Orientation.Vertical)
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
        bar.setFixedHeight(58)

        lay = QHBoxLayout(bar)
        lay.setContentsMargins(Sp.L, Sp.S, Sp.L, Sp.S)
        lay.setSpacing(0)

        # Brand
        glyph = QLabel('\u2b22')
        glyph.setObjectName('brandGlyph')
        lay.addWidget(glyph)
        lay.addSpacing(Sp.S)

        brand = QLabel('TORNADOC2')
        brand.setObjectName('brandWord')
        lay.addWidget(brand)
        lay.addSpacing(Sp.S)

        sub = QLabel('RED TEAM OPERATIONS')
        sub.setObjectName('brandSub')
        lay.addWidget(sub)
        lay.addSpacing(Sp.XL)

        chip = QFrame()
        chip.setObjectName('connChip')
        cl = QHBoxLayout(chip)
        cl.setContentsMargins(10, 3, 10, 3)
        cl.setSpacing(6)
        self.status_dot = StatusDot()
        cl.addWidget(self.status_dot)
        self.header_conn = QLabel('connecting…')
        self.header_conn.setObjectName('connInfo')
        cl.addWidget(self.header_conn)
        cl.addSpacing(4)
        self.status_pill = QLabel('OFFLINE')
        self.status_pill.setObjectName('statusPill')
        self.status_pill.setProperty('state', 'connecting')
        cl.addWidget(self.status_pill)
        lay.addWidget(chip)
        lay.addStretch(1)

        self.role_badge = QLabel('—')
        self.role_badge.setObjectName('roleBadge')
        lay.addWidget(self.role_badge)

        return bar

    def _set_connection(self, host: str, role: str) -> None:
        self.header_conn.setText(host)
        self.role_badge.setText(role.upper())
        self.status_pill.setText('ONLINE')
        self.status_pill.setProperty('state', 'online')
        self._repolish(self.status_pill)
        self.status_dot.set_color(Palette.OK)
        if hasattr(self, 'operator_lbl'):
            self.operator_lbl.setText(f"operator  {self.client.name or '?'}")
            self.role_lbl.setText(f"role  {role.upper()}")

    def _set_disconnected(self) -> None:
        self._toast('connection lost', 'err')
        self.status_pill.setText('OFFLINE')
        self.status_pill.setProperty('state', 'offline')
        self._repolish(self.status_pill)
        self.status_dot.set_color(Palette.ERR)
        for name in ('operator_lbl', 'role_lbl'):
            if hasattr(self, name):
                getattr(self, name).setText('')

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

        lbl = QLabel('TARGETS')
        lbl.setObjectName('sectionLabel')
        head.addWidget(lbl)

        self.beacon_count_lbl = QLabel('0')
        self.beacon_count_lbl.setObjectName('countBadge')
        head.addWidget(self.beacon_count_lbl)

        head.addSpacing(Sp.M)

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText('search targets…')
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
        attach.setToolTip('Attach to the selected target  (Enter)')
        attach.clicked.connect(self._attach_selected)
        head.addWidget(attach)

        detach = QPushButton('Detach')
        detach.setToolTip('Release the current target')
        detach.clicked.connect(lambda: self._submit('detach'))
        head.addWidget(detach)

        refresh = QPushButton('↻')
        refresh.setObjectName('ghost')
        refresh.setToolTip('Refresh the target list  (F5)')
        refresh.clicked.connect(self._refresh_beacons_async)
        head.addWidget(refresh)

        lay.addLayout(head)

        # ── Beacon table ─────────────────────────────────────
        self.beacon_model = BeaconModel()
        self.tree = _BeaconView()
        self.tree.setModel(self.beacon_model)
        self.tree.set_empty_text(
            'waiting for beacons\n'
            'the list updates every few seconds')
        self.tree.setSelectionBehavior(
            QTableView.SelectionBehavior.SelectRows)
        self.tree.setSelectionMode(
            QTableView.SelectionMode.ExtendedSelection)
        self.tree.setAlternatingRowColors(False)
        self.tree.setSortingEnabled(False)
        self.tree.setShowGrid(False)
        self.tree.verticalHeader().setVisible(False)
        self.tree.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(
            self._on_tree_context)
        self.tree.doubleClicked.connect(
            lambda *_: self._attach_selected())
        self.tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)

        # Column sizing. USER@HOST stretches to fill the rest;
        # everything else sizes to its content so a header like
        # "win/amd64" never truncates to "wi...64". The trade is
        # that OS and LAST re-measure on every refresh; for a
        # fleet of tens that is invisible.
        hdr = self.tree.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.setColumnWidth(0, 200)   # BEACON  (dot + id + alias)
        hdr.sectionClicked.connect(self._sort_by)
        hdr.setSectionsClickable(True)

        lay.addWidget(self.tree, 1)

        self.bulk_bar = QWidget()
        bl = QHBoxLayout(self.bulk_bar)
        bl.setContentsMargins(0, 0, 0, 0)
        self.bulk_count = QLabel('0 selected')
        self.bulk_count.setObjectName('dlgSub')
        bl.addWidget(self.bulk_count)
        bl.addStretch(1)
        for label, slot in (
                ('Task…', self._bulk_task),
                ('Tag…', self._bulk_tag),
                ('Kill…', self._bulk_kill),
                ('Clear', self.tree.clearSelection)):
            b = QPushButton(label)
            b.setObjectName('ghost')
            b.clicked.connect(slot)
            bl.addWidget(b)
        self.bulk_bar.setVisible(False)
        lay.addWidget(self.bulk_bar)
        self.tree.selectionModel().selectionChanged.connect(
            self._bulk_selection_changed)
        return pane

    # ------------------------------------------------------------------
    # Listeners panel

    # ------------------------------------------------------------------
    # Graph

    def _build_graph_tab(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(Sp.M, Sp.M, Sp.M, Sp.M)
        lay.setSpacing(Sp.S)

        top = QHBoxLayout()
        title = QLabel('Engagement graph')
        title.setObjectName('toolbarTitle')
        top.addWidget(title)
        sub = QLabel('shared identity, privilege and relay parentage')
        sub.setObjectName('dlgSub')
        top.addWidget(sub)
        top.addStretch(1)
        self.graph_mode = QComboBox()
        for label, key in (('Privilege', 'privilege'),
                           ('User', 'user'), ('Domain', 'domain'),
                           ('Subnet', 'subnet'), ('Session', 'session')):
            self.graph_mode.addItem(label, key)
        top.addWidget(self.graph_mode)
        self.graph_refresh = QPushButton('Refresh')
        self.graph_refresh.setObjectName('ghost')
        self.graph_refresh.clicked.connect(self._refresh_graph_async)
        top.addWidget(self.graph_refresh)
        fit = QPushButton('Fit')
        fit.setObjectName('ghost')
        fit.clicked.connect(self._fit_graph)
        top.addWidget(fit)
        lay.addLayout(top)

        self.graph_view = QGraphicsView()
        self.graph_view.setObjectName('graphView')
        self.graph_scene = QGraphicsScene(self)
        self.graph_view.setScene(self.graph_scene)
        self.graph_view.setRenderHint(
            QPainter.RenderHint.Antialiasing)
        self.graph_view.setDragMode(
            QGraphicsView.DragMode.ScrollHandDrag)
        lay.addWidget(self.graph_view, 1)

        legend = QLabel(
            '<span style="color:#f85149">system</span> · '
            '<span style="color:#ff8c42">admin</span> · '
            '<span style="color:#ffd166">root</span> · '
            '<span style="color:#58a6ff">user</span> · '
            '<span style="color:#6e7681">dead</span> · '
            'white ring = elevated · red edge = relay parent')
        legend.setObjectName('dlgSub')
        lay.addWidget(legend)
        self.graph_status = QLabel('refresh to build')
        self.graph_status.setObjectName('dlgSub')
        lay.addWidget(self.graph_status)

        self._graph_timer = QTimer(self)
        self._graph_timer.timeout.connect(self._refresh_graph_async)
        self._graph_timer.start(5000)
        self._refresh_graph_async()
        return pane

    def _build_engagement_tab(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(Sp.M, Sp.M, Sp.M, Sp.M)
        lay.setSpacing(Sp.S)

        top = QHBoxLayout()
        title = QLabel('Engagement')
        title.setObjectName('toolbarTitle')
        top.addWidget(title)
        sub = QLabel('observed hosts, findings and timeline')
        sub.setObjectName('dlgSub')
        top.addWidget(sub)
        top.addStretch(1)
        add = QPushButton('Add finding')
        add.setObjectName('ghost')
        add.clicked.connect(self._add_finding)
        top.addWidget(add)
        note = QPushButton('Timeline note')
        note.setObjectName('ghost')
        note.clicked.connect(self._add_timeline_note)
        top.addWidget(note)
        ev = QPushButton('Evidence')
        ev.setObjectName('ghost')
        ev.clicked.connect(self._add_evidence)
        top.addWidget(ev)
        exp = QPushButton('Report')
        exp.setObjectName('primary')
        exp.clicked.connect(self._show_report)
        top.addWidget(exp)
        ioc = QPushButton('IOC')
        ioc.setObjectName('ghost')
        ioc.clicked.connect(lambda: self._export('ioc'))
        top.addWidget(ioc)
        stix = QPushButton('STIX')
        stix.setObjectName('ghost')
        stix.clicked.connect(lambda: self._export('stix'))
        top.addWidget(stix)
        ref = QPushButton('Refresh')
        ref.setObjectName('ghost')
        ref.clicked.connect(self._refresh_engagement_async)
        top.addWidget(ref)
        lay.addLayout(top)

        split = QSplitter(Qt.Orientation.Vertical)
        self.hosts_tree = QTreeWidget()
        self.hosts_tree.setHeaderLabels(
            ['host', 'os', 'user', 'privilege', 'beacon'])
        self.hosts_tree.setRootIsDecorated(False)
        self.hosts_tree.header().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        split.addWidget(self.hosts_tree)

        self.findings_tree = QTreeWidget()
        self.findings_tree.setHeaderLabels(
            ['sev', 'host', 'title', 'detail', 'by'])
        self.findings_tree.setRootIsDecorated(False)
        self.findings_tree.header().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        split.addWidget(self.findings_tree)

        self.model_tree = QTreeWidget()
        self.model_tree.setHeaderLabels(['entity', 'host'])
        self.model_tree.header().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        split.addWidget(self.model_tree)

        self.timeline_list = QListWidget()
        split.addWidget(self.timeline_list)
        split.setSizes([220, 200, 180, 160])
        lay.addWidget(split, 1)

        self._eng_timer = QTimer(self)
        self._eng_timer.timeout.connect(self._refresh_engagement_async)
        self._eng_timer.start(10000)
        return pane

    ENG_GROUP_CAP = 200

    def _refresh_engagement_async(self) -> None:
        if not getattr(self, '_connected', False):
            return
        self._command_q.put(('callable', self._fetch_engagement_worker))

    def _fetch_engagement_worker(self) -> None:
        # A full pull every sixth cycle recovers from a wiped or
        # restored engagement whose timestamps sit behind the cursor.
        self._eng_ticks = getattr(self, '_eng_ticks', 0) + 1
        since = 0.0 if self._eng_ticks % 6 == 0 else getattr(
            self, '_eng_since', 0.0)
        try:
            data = self.client.tp.post(
                '/api/v1/model', {'since': since, 'limit': 300})
        except Exception as exc:
            self._log(f'engagement refresh failed: {exc}', 'err')
            return
        self.sig_engagement.emit(data)

    def _apply_engagement(self, data) -> None:
        """Render only when the dataset changed, keeping the view."""
        data = data or {}
        dataset = data.get('dataset') or ''
        if dataset and dataset == getattr(self, '_eng_dataset', ''):
            return
        self._eng_dataset = dataset
        timeline = data.get('timeline') or []
        if timeline:
            self._eng_since = max(
                float(t.get('ts') or 0) for t in timeline)

        expanded = set()
        for i in range(self.model_tree.topLevelItemCount()):
            item = self.model_tree.topLevelItem(i)
            if item and item.isExpanded():
                expanded.add(item.text(0))
        selected = self.model_tree.currentItem()
        selected_key = selected.text(0) if selected else ''

        self.hosts_tree.clear()
        for h in data.get('hosts') or []:
            QTreeWidgetItem(self.hosts_tree, [
                h.get('hostname') or h.get('machine_id') or '',
                h.get('os', ''), h.get('user', ''),
                h.get('privilege', ''), str(h.get('beacon_id', ''))])
        self.findings_tree.clear()
        for f in data.get('findings') or []:
            QTreeWidgetItem(self.findings_tree, [
                f.get('severity', '').upper(), f.get('host', ''),
                f.get('title', ''), f.get('detail', ''), f.get('by', '')])
        self.model_tree.clear()
        for key, label in (('users', 'user'), ('shares', 'share'),
                           ('services', 'service'),
                           ('evidence', 'evidence')):
            rows = data.get(key) or []
            parent = QTreeWidgetItem(self.model_tree,
                                     [f"{label} ({len(rows)})", ''])
            for row in rows[:self.ENG_GROUP_CAP]:
                name = (row.get('user') or row.get('name') or
                        row.get('sha256', ''))
                child = QTreeWidgetItem([name, row.get('host', '')])
                parent.addChild(child)
                if name == selected_key:
                    self.model_tree.setCurrentItem(child)
            if len(rows) > self.ENG_GROUP_CAP:
                QTreeWidgetItem(
                    parent, [f"… {len(rows) - self.ENG_GROUP_CAP} more",
                             ''])
            parent.setExpanded(label in expanded or not expanded)
        for e in reversed(timeline):
            import time as _t
            stamp = _t.strftime('%H:%M', _t.localtime(e.get('ts', 0)))
            self.timeline_list.addItem(
                f"{stamp}  {e.get('kind')}: {e.get('text')}")
        while self.timeline_list.count() > 2000:
            self.timeline_list.takeItem(0)

    def _add_finding(self) -> None:
        sev, ok = QInputDialog.getItem(
            self, 'Finding', 'Severity',
            ['info', 'low', 'medium', 'high', 'critical'], 2, False)
        if not ok:
            return
        host, ok = QInputDialog.getText(self, 'Finding', 'Host')
        if not ok or not host.strip():
            return
        title, ok = QInputDialog.getText(self, 'Finding', 'Title')
        if not ok or not title.strip():
            return
        detail, ok = QInputDialog.getText(self, 'Finding', 'Detail')
        if not ok:
            return
        self._bg_post('/api/v1/findings', {
            'severity': sev, 'host': host, 'title': title,
            'detail': detail})
        self._refresh_engagement_async()

    def _add_evidence(self) -> None:
        sha, ok = QInputDialog.getText(self, 'Evidence', 'SHA-256')
        if not ok or len(sha.strip()) != 64:
            return
        name, ok = QInputDialog.getText(self, 'Evidence', 'Name')
        if not ok or not name.strip():
            return
        host, ok = QInputDialog.getText(self, 'Evidence', 'Host')
        if not ok:
            return
        detail, ok = QInputDialog.getText(self, 'Evidence', 'Detail')
        if not ok:
            return
        self._bg_post('/api/v1/evidence', {
            'sha256': sha.strip(), 'name': name, 'host': host,
            'detail': detail})
        self._refresh_engagement_async()

    def _export(self, kind: str) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, f'Export {kind.upper()}', f'engagement.{kind}',
            'All files (*)')
        if not path:
            return
        self._status(f'exporting {kind}…')

        def work():
            try:
                if kind == 'report':
                    body = self.client.tp.post(
                        '/api/v1/report', {}).get('markdown', '')
                else:
                    r = self.client.tp.post(
                        f'/api/v1/export/{kind}', {})
                    body = (r.get('csv') if kind == 'ioc'
                            else json.dumps(r.get('bundle'), indent=2))
            except Exception as exc:
                msg = str(exc)
                self.sig_post.emit(
                    lambda: self._log(f'export {kind} failed: {msg}',
                                      'err'))
                return
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT
                             | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                    fh.write(body or '')
            except OSError as exc:
                msg = str(exc)
                self.sig_post.emit(
                    lambda: self._log(f'write {path} failed: {msg}',
                                      'err'))
                return
            self.sig_post.emit(
                lambda: self._status(f'exported {path}'))
            self.sig_post.emit(
                lambda: self._toast(f'exported {os.path.basename(path)}',
                                    'ok'))

        self._run_bg(work, f'export {kind}')

    def _add_timeline_note(self) -> None:
        text, ok = QInputDialog.getText(self, 'Timeline', 'Note')
        if ok and text.strip():
            self._bg_post('/api/v1/timeline',
                          {'kind': 'note', 'text': text})
            self._refresh_engagement_async()

    def _show_report(self) -> None:
        self._status('building report…')

        def work():
            try:
                md = self.client.tp.post(
                    '/api/v1/report', {}).get('markdown')
            except Exception as exc:
                msg = str(exc)
                self.sig_post.emit(
                    lambda: self._log(f'report failed: {msg}', 'err'))
                return
            self.sig_post.emit(lambda: self._report_dialog(md or ''))

        self._run_bg(work, 'report')

    def _report_dialog(self, md: str) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle('Engagement report')
        dlg.resize(760, 620)
        lay = QVBoxLayout(dlg)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setPlainText(md or '')
        lay.addWidget(view, 1)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(dlg.reject)
        bb.clicked.connect(dlg.accept)
        copy = QPushButton('Copy')
        copy.clicked.connect(
            lambda: QApplication.clipboard().setText(md or ''))
        bb.addButton(copy, QDialogButtonBox.ButtonRole.ActionRole)
        lay.addWidget(bb)
        dlg.exec()

    MAX_INFLIGHT = 8

    LIGHT_QSS = """
QMainWindow, QDialog, QWidget { background: #f6f7f9; color: #1c2128; }
QWidget#headerBar { background: #eef1f5; }
QPlainTextEdit, QLineEdit, QComboBox, QTreeWidget, QTableView,
QListWidget, QTextEdit { background: #ffffff; color: #1c2128;
    border-color: #c9d0d9; }
QHeaderView::section { background: #e6eaef; color: #1c2128; }
QPushButton { background: #e6eaef; color: #1c2128; }
QLabel#toolbarTitle { color: #1c2128; }
"""

    COMPACT_QSS = """
QTreeWidget::item, QTableView::item, QListWidget::item {
    padding-top: 1px; padding-bottom: 1px; }
QPlainTextEdit#logView { font-size: 9pt; }
"""

    def _apply_theme(self) -> None:
        extra = ''
        if getattr(self, '_light', False):
            extra += self.LIGHT_QSS
        if getattr(self, '_compact', False):
            extra += self.COMPACT_QSS
        self.setStyleSheet(STYLESHEET + extra)
        if self._light:
            self.tree.setStyleSheet(
                'QTableView { background: #ffffff; color: #1c2128; }')
        else:
            self.tree.setStyleSheet('')

    def _toggle_light(self) -> None:
        self._light = not getattr(self, '_light', False)
        self._apply_theme()

    def _toggle_compact(self) -> None:
        self._compact = not getattr(self, '_compact', False)
        self._apply_theme()

    def _toast(self, text: str, sev: str = 'info') -> None:
        """Transient corner message, at most four at a time."""
        if not hasattr(self, '_toast_lay'):
            return
        colour = {'info': Palette.CYAN, 'ok': Palette.OK,
                  'warn': Palette.WARN, 'err': Palette.ERR}.get(
                      sev, Palette.TEXT)
        lbl = QLabel(text[:200])
        lbl.setWordWrap(True)
        lbl.setStyleSheet(
            f'background: {Palette.BG_SOFT}; color: {colour}; '
            f'border: 1px solid {colour}; border-radius: 6px; '
            f'padding: 6px 10px;')
        self._toast_lay.insertWidget(0, lbl)
        while self._toast_lay.count() > 5:
            old = self._toast_lay.itemAt(
                self._toast_lay.count() - 2)
            if old and old.widget():
                old.widget().deleteLater()
                self._toast_lay.removeItem(old)
            else:
                break
        QTimer.singleShot(4000, lambda: self._drop_toast(lbl))

    def _drop_toast(self, lbl) -> None:
        try:
            self._toast_lay.removeWidget(lbl)
            lbl.deleteLater()
        except RuntimeError:
            pass

    def resizeEvent(self, ev) -> None:
        super().resizeEvent(ev)
        if hasattr(self, 'toasts'):
            self.toasts.setGeometry(0, 0, self.width(),
                                    max(0, self.height() // 2))

    def _run_bg(self, fn, label: str, timeout: float = 180.0) -> None:
        """Queue one background call with busy accounting.

        The queue is bounded in practice by MAX_INFLIGHT: a burst of
        clicks is refused with a visible message instead of growing
        a thread per click.
        """
        if getattr(self, '_inflight', 0) >= self.MAX_INFLIGHT:
            self._log(f'{label}: too many requests in flight', 'warn')
            self._status('busy — wait for a request to finish')
            return
        self._inflight = getattr(self, '_inflight', 0) + 1
        token = {'done': False}

        def finish(msg=None, tag='meta'):
            if token['done']:
                return
            token['done'] = True
            self._inflight = max(0, self._inflight - 1)
            if msg:
                self._log(msg, tag)

        def watchdog():
            if token['done']:
                return
            finish(f'{label} timed out after {int(timeout)}s', 'err')

        QTimer.singleShot(int(timeout * 1000), watchdog)

        def work():
            try:
                fn()
                msg, tag = None, 'meta'
            except Exception as exc:
                msg, tag = f'{label} failed: {exc}', 'err'
            self.sig_post.emit(lambda: finish(msg, tag))

        self._command_q.put(('callable', work))

    def _bg_post(self, path, payload) -> None:
        self._run_bg(lambda: self.client.tp.post(path, payload),
                     path.rsplit('/', 1)[-1])

    def _refresh_graph_async(self) -> None:
        if not getattr(self, '_connected', False):
            return
        self._command_q.put(('callable', self._fetch_graph_worker))

    def _fetch_graph_worker(self) -> None:
        try:
            data = self.client.tp.post('/api/v1/graph',
                                       {'mode': 'json'})
        except Exception as exc:
            self._log(f'graph refresh failed: {exc}', 'err')
            return
        self.sig_graph.emit(data)

    def _fit_graph(self) -> None:
        if self.graph_scene.items():
            self.graph_view.fitInView(
                self.graph_scene.itemsBoundingRect(),
                Qt.AspectRatioMode.KeepAspectRatio)
            self.graph_view.resetTransform()
            self.graph_view.scale(1, 1)
            self.graph_view.fitInView(
                self.graph_scene.itemsBoundingRect(),
                Qt.AspectRatioMode.KeepAspectRatio)

    def _apply_graph(self, data) -> None:
        nodes = (data or {}).get('nodes') or []
        edges = (data or {}).get('edges') or []
        self.graph_scene.clear()
        if not nodes:
            self.graph_scene.addText(
                'no beacons — graph is empty')
            self.graph_status.setText('0 nodes')
            return

        mode = self.graph_mode.currentData() or 'privilege'
        groups = {}
        for n in nodes:
            key = n.get(mode) or n.get('user') or '(unknown)'
            groups.setdefault(str(key), []).append(n)
        ordered = sorted(groups.items())

        positions = {}
        for gi, (_key, members) in enumerate(ordered):
            x = 100 + gi * 210
            for ri, n in enumerate(sorted(members,
                                          key=lambda z: z['id'])):
                positions[n['id']] = (x, 70 + ri * 82)

        for e in edges:
            a = positions.get(e.get('from'))
            b = positions.get(e.get('to'))
            if not a or not b:
                continue
            relay = 'relay-parent' in (e.get('shared') or [])
            pen = QPen(QColor(Palette.ERR if relay else Palette.BORDER))
            pen.setWidth(2 if relay else 1)
            if not relay:
                pen.setStyle(Qt.PenStyle.DashLine)
            self.graph_scene.addLine(
                a[0] + 75, a[1] + 26, b[0] + 75, b[1] + 26, pen)

        colors = {
            'system': '#f85149', 'root': '#ffd166',
            'admin': '#ff8c42', 'user': Palette.ACCENT,
        }
        for n in nodes:
            pos = positions.get(n['id'])
            if not pos:
                continue
            priv = (n.get('privilege') or 'user').lower()
            if not n.get('alive'):
                fill = Palette.TEXT_FAINT
            else:
                fill = colors.get(priv, Palette.ACCENT)
            pen = QPen(QColor(Palette.TEXT_INVERT if n.get('elevated')
                              else Palette.BORDER))
            pen.setWidth(2 if n.get('elevated') else 1)
            path = QPainterPath()
            path.addRoundedRect(pos[0], pos[1], 150, 52, 8, 8)
            item = QGraphicsPathItem(path)
            item.setBrush(QBrush(QColor(Palette.BG_SOFT)))
            item.setPen(pen)
            item.setToolTip(
                f"#{n['id']} {n['name']}\n"
                f"{n.get('user') or '?'}@{n.get('domain') or ''}\n"
                f"{priv} integrity={n.get('integrity') or '?'}\n"
                f"parent={n.get('parent_name') or '?'} "
                f"({n.get('parent_pid') or 0})")
            self.graph_scene.addItem(item)
            stripe = QGraphicsRectItem(pos[0], pos[1], 4, 52)
            stripe.setBrush(QBrush(QColor(fill)))
            stripe.setPen(QPen(Qt.PenStyle.NoPen))
            self.graph_scene.addItem(stripe)
            label = QGraphicsTextItem(
                f"#{n['id']}  {n['name']}")
            label.setDefaultTextColor(QColor(Palette.TEXT))
            label.setFont(_f_ui(9, bold=True))
            label.setPos(pos[0] + 12, pos[1] + 7)
            self.graph_scene.addItem(label)
            sub = QGraphicsTextItem(
                f"{priv.upper()}  ·  {n.get('user') or '?'}")
            sub.setDefaultTextColor(QColor(fill))
            sub.setFont(_f_mono(8))
            sub.setPos(pos[0] + 12, pos[1] + 28)
            self.graph_scene.addItem(sub)

        self.graph_scene.setSceneRect(
            self.graph_scene.itemsBoundingRect().adjusted(
                -20, -20, 20, 20))
        self.graph_status.setText(
            f"{len(nodes)} node(s), {len(edges)} edge(s), "
            f"grouped by {mode}")

    def _build_listeners_tab(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(Sp.M, Sp.M, Sp.M, Sp.M)
        lay.setSpacing(Sp.M)

        can_view = 'listener.view' in getattr(self.client, 'caps', ())
        if not can_view:
            lbl = QLabel(
                'This role may not include listener.view. Operator, '
                'admin and local can view and manage listeners.')
            lbl.setWordWrap(True)
            lbl.setObjectName('callout')
            lay.addWidget(lbl)

        top = QHBoxLayout()
        tcol = QVBoxLayout()
        tcol.setSpacing(2)
        title = QLabel('Beacon listeners')
        title.setObjectName('toolbarTitle')
        tcol.addWidget(title)
        sub = QLabel(
            'Persisted to listeners.json · survives restart · '
            'visible to the whole team')
        sub.setObjectName('dlgSub')
        tcol.addWidget(sub)
        top.addLayout(tcol)
        self.listener_count = QLabel('0')
        self.listener_count.setObjectName('countBadge')
        top.addWidget(self.listener_count, 0, Qt.AlignmentFlag.AlignTop)
        top.addStretch(1)
        self.listener_refresh_btn = QPushButton('Refresh')
        self.listener_refresh_btn.setObjectName('ghost')
        self.listener_refresh_btn.clicked.connect(
            self._refresh_listeners_async)
        top.addWidget(self.listener_refresh_btn)
        self.listener_create_btn = QPushButton('Create listener')
        self.listener_create_btn.setObjectName('primary')
        self.listener_create_btn.clicked.connect(
            lambda: self._open_listener_dialog(False))
        top.addWidget(self.listener_create_btn)
        lay.addLayout(top)

        split = QSplitter(Qt.Orientation.Horizontal)
        lay.addWidget(split, 1)

        self.listener_tree = QTreeWidget()
        self.listener_tree.setRootIsDecorated(False)
        self.listener_tree.setAlternatingRowColors(True)
        self.listener_tree.setSelectionMode(
            QTreeWidget.SelectionMode.SingleSelection)
        self.listener_tree.setUniformRowHeights(True)
        self.listener_tree.setHeaderLabels([
            'ID', 'NAME', 'TYPE', 'BIND', 'STATUS',
            'PROFILES', 'CREATED BY', 'HEALTH'])
        hdr = self.listener_tree.header()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.listener_tree.itemSelectionChanged.connect(
            self._on_listener_selected)
        split.addWidget(self.listener_tree)

        card = QFrame()
        card.setObjectName('detailCard')
        dlay = QVBoxLayout(card)
        dlay.setContentsMargins(14, 12, 14, 12)
        dlay.setSpacing(8)

        head = QHBoxLayout()
        self.listener_name = QLabel('No selection')
        self.listener_name.setFont(_f_ui(12, bold=True))
        head.addWidget(self.listener_name)
        self.listener_status = QLabel('—')
        self.listener_status.setObjectName('statusPill')
        head.addWidget(self.listener_status)
        head.addStretch(1)
        dlay.addLayout(head)

        self.listener_detail = QLabel(
            'Select a listener to inspect its bind, profiles and '
            'state.\n\nA listener opened here survives restart '
            'and is visible to the whole team.')
        self.listener_detail.setWordWrap(True)
        self.listener_detail.setTextFormat(
            Qt.TextFormat.RichText)
        self.listener_detail.setAlignment(
            Qt.AlignmentFlag.AlignTop)
        dlay.addWidget(self.listener_detail, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self.listener_buttons = {}
        for label, action, cap, style in (
                ('Start', 'start', 'listener.manage', 'primary'),
                ('Stop', 'stop', 'listener.manage', None),
                ('Edit', 'edit', 'listener.manage', None),
                ('Delete', 'delete', 'listener.delete', 'danger')):
            b = QPushButton(label)
            if style:
                b.setObjectName(style)
            b.clicked.connect(
                lambda _=False, a=action: self._listener_do(a))
            b.setEnabled(False)
            if cap not in getattr(self.client, 'caps', ()):
                b.setToolTip('role lacks ' + cap)
            self.listener_buttons[action] = b
            btn_row.addWidget(b)
        dlay.addLayout(btn_row)
        split.addWidget(card)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([620, 380])

        self._refresh_listeners_async()
        return pane

    def _refresh_listeners_async(self) -> None:
        if (getattr(self, 'listener_tree', None) is None
                or not self._connected):
            return
        self._command_q.put(('callable', self._fetch_listeners_worker))

    def _fetch_listeners_worker(self) -> None:
        try:
            r = self.client.listener_list()
        except Exception as exc:
            self._log(f"listener refresh failed: {exc}", 'err')
            return
        self.client.listeners = list(r.get('listeners') or [])
        self.sig_listeners.emit(self.client.listeners)

    @Slot(object)
    def _apply_listener_rows(self, rows) -> None:
        self._listener_rows = list(rows or [])
        self._render_listeners()

    def _render_listeners(self) -> None:
        if getattr(self, 'listener_tree', None) is None:
            return
        keep = self._listener_selected
        self.listener_tree.clear()
        if hasattr(self, 'listener_count'):
            self.listener_count.setText(str(len(self._listener_rows)))
        if not self._listener_rows:
            self.listener_name.setText('No listeners')
            self.listener_status.setText('—')
            self._set_status_pill('')
            self.listener_detail.setText(
                '<div style="color:%s; font-size:12pt; '
                'font-weight:600; margin-bottom:6px;">'
                'No listeners configured</div>'
                'Open a port with <b>Create listener</b>. The '
                'configuration is persisted, survives a restart and '
                'is visible to the whole team.'
                % Palette.TEXT_MUTED)
            for b in getattr(self, 'listener_buttons', {}).values():
                b.setEnabled(False)
            return
        for lst in self._listener_rows:
            item = QTreeWidgetItem([
                lst.get('id') or '',
                lst.get('name') or '',
                lst.get('type') or '',
                f"{lst.get('host') or ''}:{lst.get('port') or ''}",
                lst.get('status') or 'stopped',
                ', '.join(lst.get('profiles') or []),
                lst.get('created_by') or '',
                lst.get('health') or 'unknown',
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, lst.get('id'))
            if lst.get('status') == 'error':
                item.setForeground(
                    4, QBrush(QColor(Palette.ERR)))
            elif lst.get('status') == 'running':
                item.setForeground(
                    4, QBrush(QColor(Palette.OK)))
            health = lst.get('health') or 'unknown'
            item.setForeground(7, QBrush(QColor({
                'ok': Palette.OK, 'degraded': Palette.WARN,
                'down': Palette.ERR}.get(health,
                                         Palette.TEXT_FAINT))))
            days = lst.get('cert_days_left')
            if isinstance(days, int) and days >= 0 and days <= 30:
                item.setToolTip(7, f'certificate expires in {days} day(s)')
            self.listener_tree.addTopLevelItem(item)
            if lst.get('id') == keep:
                item.setSelected(True)
        self._on_listener_selected()

    def _selected_listener(self):
        if getattr(self, 'listener_tree', None) is None:
            return None
        items = self.listener_tree.selectedItems()
        if not items:
            return None
        lid = items[0].data(0, Qt.ItemDataRole.UserRole)
        for lst in self._listener_rows:
            if lst.get('id') == lid:
                return lst
        return None

    def _on_listener_selected(self) -> None:
        lst = self._selected_listener()
        self._listener_selected = lst.get('id') if lst else None
        from html import escape
        can_manage = 'listener.manage' in getattr(
            self.client, 'caps', ())
        can_delete = 'listener.delete' in getattr(
            self.client, 'caps', ())
        status = (lst or {}).get('status', 'stopped')
        for action, b in getattr(
                self, 'listener_buttons', {}).items():
            if lst is None:
                b.setEnabled(False)
                continue
            if action == 'start':
                b.setEnabled(can_manage and status != 'running')
            elif action == 'stop':
                b.setEnabled(can_manage and status == 'running')
            elif action == 'edit':
                b.setEnabled(can_manage)
            else:
                b.setEnabled(can_delete and status != 'running')
        if lst is None:
            self.listener_name.setText('No selection')
            self.listener_status.setText('—')
            self._set_status_pill('')
            self.listener_detail.setText(
                'Select a listener to inspect its bind, profiles and '
                'state.')
            return
        self.listener_name.setText(lst.get('name') or '?')
        self.listener_status.setText(status)
        self._set_status_pill(status)
        err = lst.get('error_message') or ''
        dim = Palette.TEXT_FAINT
        rows = [
            ('ID', lst.get('id') or ''),
            ('Type', lst.get('type') or ''),
            ('Bind', f"{lst.get('host') or ''}:{lst.get('port') or ''}"),
        ]
        if lst.get('public_host'):
            rows.append(('Public host', lst['public_host']))
        if lst.get('domain'):
            rows.append(('Zone', lst['domain']))
        if lst.get('profiles'):
            rows.append(('Profiles', ', '.join(lst['profiles'])))
        if lst.get('subnet'):
            rows.append(('Subnet', lst['subnet']))
        if lst.get('server_tunnel_ip'):
            rows.append(('Server tunnel IP', lst['server_tunnel_ip']))
        if lst.get('created_by'):
            rows.append(('Created by', lst['created_by']))
        html_rows = ''.join(
            f'<tr><td style="color:{dim}; padding:2px 14px 2px 0;">'
            f'{escape(str(k))}</td>'
            f'<td style="padding:2px 0;">{escape(str(v))}</td></tr>'
            for k, v in rows)
        body = f'<table cellspacing="0" cellpadding="0">{html_rows}</table>'
        if err:
            body += (f'<div style="color:{Palette.ERR}; '
                     f'margin-top:10px;">{escape(err)}</div>')
        self.listener_detail.setText(body)

    def _set_status_pill(self, status) -> None:
        if not hasattr(self, 'listener_status'):
            return
        self.listener_status.setProperty('state', status or '')
        self.listener_status.style().unpolish(self.listener_status)
        self.listener_status.style().polish(self.listener_status)

    def _ensure_listener_aux(self, then) -> None:
        if self._listener_certs is not None \
                and self._listener_profiles is not None:
            then()
            return

        def work():
            try:
                certs = self.client.listener_certs()
                self.sig_listener_certs.emit(certs or {})
            except Exception as exc:
                self._log(f"cert list failed: {exc}", 'err')
                self.sig_listener_certs.emit(
                    {'certs': [], 'keys': [], 'cas': []})
            try:
                prof = self.client.tp.post(
                    '/api/v1/c2-profiles', {})
                self.sig_listener_profiles.emit(
                    list(prof.get('profiles') or []))
            except Exception as exc:
                self._log(f"profile list failed: {exc}", 'err')
                self.sig_listener_profiles.emit([])
            self.sig_post.emit(then)

        threading.Thread(target=work, daemon=True).start()

    def _open_listener_dialog(self, edit: bool) -> None:
        if 'listener.manage' not in getattr(
                self.client, 'caps', ()):
            self._log('role lacks listener.manage', 'err')
            return
        lst = self._selected_listener() if edit else None
        if edit and lst is None:
            self._status('select a listener first')
            return
        self._ensure_listener_aux(
            lambda: self._show_listener_dialog(lst))

    def _show_listener_dialog(self, lst) -> None:
        dlg = _ListenerDialog(
            self,
            self._listener_certs or {},
            self._listener_profiles or [],
            lst)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        spec = dlg.spec()
        if spec is None:
            return
        if lst is None:
            fn = lambda: self.client.listener_create(spec)
            label = 'create'
        else:
            fn = lambda: self.client.listener_update(
                lst['id'], spec)
            label = 'update'
        self._run_listener_call(fn, label)

    def _listener_do(self, action: str) -> None:
        lst = self._selected_listener()
        if lst is None:
            return
        lid = lst['id']
        if action == 'edit':
            self._open_listener_dialog(True)
            return
        if action == 'delete':
            ans = QMessageBox.question(
                self, 'Delete listener',
                f"Delete {lst.get('name')!r} ({lid})?\n"
                'The listener must be stopped first.')
            if ans != QMessageBox.StandardButton.Yes:
                return
            fn = lambda: self.client.listener_delete(lid)
        elif action == 'start':
            fn = lambda: self.client.listener_start(lid)
        else:
            fn = lambda: self.client.listener_stop(lid)
        self._run_listener_call(fn, action)

    def _run_listener_call(self, fn, label: str) -> None:
        def work():
            try:
                r = fn()
            except Exception as exc:
                msg = str(exc)
                self.sig_post.emit(
                    lambda: self._status(f'{label} failed: {msg}'))
                return
            if not r.get('ok'):
                msg = r.get('error', 'failed')
                self.sig_post.emit(
                    lambda: self._status(f'{label} failed: {msg}'))
                return
            self.sig_post.emit(
                lambda: self._status(f'listener {label} ok'))
            self.sig_post.emit(self._refresh_listeners_async)

        threading.Thread(target=work, daemon=True).start()

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
        self.tabs.addTab(log_tab, '  ▤  Log  ')

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
        self.tabs.addTab(chat_tab, '  ◈  Chat  ')

        # ── Listeners tab
        self.tabs.addTab(self._build_listeners_tab(),
                         '  ◉  Listeners  ')

        # ── Graph tab
        self.tabs.addTab(self._build_graph_tab(), '  ⌁  Graph  ')

        # ── AI tab
        self.ai_panel = _AiPanel(self)
        self.tabs.addTab(self.ai_panel, '  ✦  AI  ')
        self.tabs.addTab(self._build_engagement_tab(),
                         '  ◇  Engagement  ')

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
        self.input_bar = inp_wrap
        inp_lay = QHBoxLayout(inp_wrap)
        inp_lay.setContentsMargins(Sp.M, 2, 6, 2)
        inp_lay.setSpacing(4)
        inp_lay.addWidget(self.prompt_lbl)
        inp_lay.addWidget(self.input_entry, 1)
        inp_lay.addWidget(self.send_btn)
        lay.addWidget(inp_wrap)

        self.tabs.currentChanged.connect(
            lambda _i: self._on_tab_change())

        self.input_entry.set_history(self._history)
        self._on_tab_change()
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

        for name in ('operator_lbl', 'role_lbl'):
            lbl = QLabel('')
            lbl.setObjectName('statusMeta')
            setattr(self, name, lbl)
            sb.addPermanentWidget(lbl)
        self.mode_lbl = QLabel('MULTIPLAYER')
        self.mode_lbl.setObjectName('statusMeta')
        sb.addPermanentWidget(self.mode_lbl)

        self.clock_lbl = QLabel('')
        self.clock_lbl.setFont(_f_mono(9))
        self.clock_lbl.setStyleSheet(f'color: {Palette.TEXT_FAINT};')
        sb.addPermanentWidget(self.clock_lbl)

    def _tick_clock(self) -> None:
        self.clock_lbl.setText(time.strftime('%H:%M:%S'))

    # ------------------------------------------------------------------
    # Shortcuts

    def _bind_shortcuts(self) -> None:
        for sc in getattr(self, '_shortcuts', []):
            try:
                sc.setEnabled(False)
                sc.deleteLater()
            except RuntimeError:
                pass
        table = (
            ('quit', self._quit), ('clear_log', self._clear_log),
            ('build', self._menu_build),
            ('chat', lambda: self._submit('chat')),
            ('tab_log', lambda: self._select_tab(0)),
            ('tab_chat', lambda: self._select_tab(1)),
            ('tab_graph', lambda: self._select_tab(3)),
            ('tab_listeners', lambda: self._select_tab(2)),
            ('refresh', self._refresh_beacons_async),
            ('palette', self._open_palette),
            ('spawnto', self._prompt_spawnto_selected),
        )
        self._shortcuts = []
        for name, slot in table:
            seq = self._keys.get(name) or KEY_DEFAULTS[name]
            sc = QShortcut(QKeySequence(seq), self, activated=slot)
            self._shortcuts.append(sc)
        self._shortcuts.append(QShortcut(
            QKeySequence('Ctrl+C'), self,
            context=Qt.ShortcutContext.ApplicationShortcut,
            activated=self._on_copy_or_clear))
        self._shortcuts.append(QShortcut(
            QKeySequence('Ctrl+Shift+C'), self,
            context=Qt.ShortcutContext.ApplicationShortcut,
            activated=self._on_copy_only))

    def _keymap_dialog(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle('Keybindings')
        lay = QVBoxLayout(dlg)
        form = QFormLayout()
        lay.addLayout(form)
        edits = {}
        for name, label in (
                ('palette', 'Command palette'), ('refresh', 'Refresh'),
                ('build', 'Build agent'), ('spawnto', 'Set spawnto'),
                ('tab_log', 'Log tab'), ('tab_chat', 'Chat tab'),
                ('tab_graph', 'Graph tab'),
                ('tab_listeners', 'Listeners tab'),
                ('chat', 'Chat'), ('clear_log', 'Clear log'),
                ('quit', 'Quit')):
            ed = QKeySequenceEdit(QKeySequence(self._keys[name]))
            form.addRow(label, ed)
            edits[name] = ed
        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(lambda: self._save_keys(dlg, edits))
        bb.rejected.connect(dlg.reject)
        lay.addWidget(bb)
        dlg.exec()

    def _save_keys(self, dlg, edits) -> None:
        seen = {}
        new = {}
        for name, ed in edits.items():
            seq = ed.keySequence().toString()
            if not seq:
                seq = KEY_DEFAULTS[name]
            if seq in seen:
                QMessageBox.warning(
                    dlg, 'Duplicate',
                    f'{seq} is used by {seen[seq]} and {name}')
                return
            seen[seq] = name
            new[name] = seq
        self._keys = new
        self._bind_shortcuts()
        self._save_state()
        dlg.accept()


    def _select_tab(self, idx: int) -> None:
        self.tabs.setCurrentIndex(idx)

    def _on_tab_change(self) -> None:
        idx = self.tabs.currentIndex()
        self._chat_tab_active = (idx == 1)
        # Listeners and AI own their inputs; the beacon command
        # bar would only be confusing there.
        if hasattr(self, 'input_bar'):
            self.input_bar.setVisible(idx in (0, 1))
        if idx == 4:
            self.ai_panel.entry.setFocus()
        elif idx == 3:
            self.graph_view.setFocus()
        elif idx == 2:
            self.listener_tree.setFocus()
        elif idx in (0, 1):
            self.input_entry.setFocus()
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
        try:
            self._save_state()
        except Exception:
            pass
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

        rendered = []
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

            viewers = b.get('viewers') or []
            if not viewers:
                view_text = '—'
            elif len(viewers) == 1:
                view_text = viewers[0].get('name', '?')
            else:
                view_text = f"+{len(viewers)}"

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
            alias = (b.get('alias') or '').strip()
            beacon_cell = (f"{dot}  {b['id']}  {alias}" if alias
                           else f"{dot}  {b['id']}")

            priv = (b.get('privilege') or 'user').lower()
            if b.get('elevated'):
                priv += '!'

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
                f"platform    : {b.get('os','?')}/{arch_raw}\n"
                f"address     : {addr}\n"
                f"sleep       : {sleep}s\n"
                f"check-ins   : {checkins}\n"
                f"last seen   : {age_s} ago\n"
                f"spawnto     : {spawnto_note}\n"
                f"privilege   : {priv}\n"
                f"integrity   : {b.get('integrity') or '?'}\n"
                f"parent      : {b.get('parent_name') or '?'}\n"
                f"fingerprint : {fp}…"
            )

            if live:
                beacon_color = QColor(Palette.OK)
            else:
                beacon_color = QColor(Palette.TEXT_FAINT)
            body_color = QColor(Palette.TEXT)
            if not viewers:
                view_color = QColor(Palette.TEXT_FAINT)
            elif len(viewers) == 1:
                view_color = QColor(Palette.CYAN)
            else:
                view_color = QColor(Palette.WARN)
            if priv.startswith('system'):
                priv_color = QColor(Palette.ERR)
            elif priv.startswith('root'):
                priv_color = QColor(Palette.PRIV_ROOT)
            elif priv.startswith('admin'):
                priv_color = QColor(Palette.PRIV_ADMIN)
            else:
                priv_color = QColor(Palette.TEXT_MUTED)

            tint = None
            if live:
                tint = QColor(Palette.OK)
                tint.setAlpha(14)

            rendered.append({
                'id': b['id'],
                'cells': [beacon_cell, b.get('display_name') or '?',
                          priv, plat, age_s, view_text],
                'tip': tip,
                'colors': [beacon_color, body_color, priv_color,
                           QColor(Palette.TEXT_MUTED),
                           QColor(Palette.TEXT_MUTED), view_color],
                'tint': tint,
            })

        self.beacon_model.set_view(rendered)

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
        sel = self.tree.selectionModel()
        if sel is None:
            return ''
        rows = sel.selectedRows()
        if not rows:
            return ''
        return self.beacon_model.id_at(rows[0].row())

    def _bulk_selection_changed(self, *_a) -> None:
        n = len(self._selected_ids())
        self.bulk_bar.setVisible(n >= 2)
        self.bulk_count.setText(f'{n} selected')

    def _bulk_ids(self) -> str:
        return ','.join(self._selected_ids())

    def _bulk_task(self) -> None:
        ids = self._bulk_ids()
        if not ids:
            return
        line, ok = QInputDialog.getText(
            self, 'Bulk task', f'Command for {len(self._selected_ids())} '
                                f'beacons (sent as `sh`)')
        if not ok or not line.strip():
            return
        parts = line.strip().split(' ', 1)
        tail = f" {parts[1]}" if len(parts) > 1 else ''
        self._submit(f'bulk task {ids} {parts[0]}{tail}')

    def _bulk_tag(self) -> None:
        ids = self._bulk_ids()
        if not ids:
            return
        tag, ok = QInputDialog.getText(self, 'Bulk tag', 'Tag')
        if ok and tag.strip():
            self._submit(f'bulk tag {tag.strip()} {ids}')

    def _bulk_kill(self) -> None:
        ids = self._bulk_ids()
        if not ids:
            return
        n = len(self._selected_ids())
        if QMessageBox.question(
                self, 'Kill', f'Kill {n} beacons?') != \
                QMessageBox.StandardButton.Yes:
            return
        self._submit(f'bulk kill {ids}')

    def _selected_ids(self) -> list:
        sel = self.tree.selectionModel()
        if sel is None:
            return []
        return [self.beacon_model.id_at(i.row())
                for i in sel.selectedRows()]

    def _attach_selected(self) -> None:
        sel = self._selected_id()
        if sel:
            self._submit(f"use {sel}")

    def _on_tree_context(self, pos: QPoint) -> None:
        index = self.tree.indexAt(pos)
        if not index.isValid():
            return
        self.tree.setCurrentIndex(index)

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
        """Keep the input bar enabled at all times.

        The input used to be disabled while `_busy` was set —
        again matching the Tk version rather than the CLI.
        Since submission is now always accepted (see
        `_submit`), disabling the widget only hides the
        operator's ability to queue a follow-up command.
        The status bar still reports the worker's state for
        anyone who wants to know; the input itself is always
        usable.
        """
        self.input_entry.setEnabled(True)

    def _submit(self, line: str) -> None:
        """Queue a command for the worker thread.

        Submission is always accepted. The queue behind the
        worker is unbounded and processes in FIFO order, so
        there is no correctness reason to refuse a command
        while another is running. The CLI behaves the same
        way: `_dispatch_task` returns as soon as the task is
        acked by the server, and the operator can type the
        next command immediately. Blocking submission here
        made the GUI feel slower than the CLI for no gain.

        The worker thread still processes one item at a time,
        so a slow blocking verb (`execute-assembly`,
        `hashdump`, a large `upload`) delays the queued
        follow-ups. The status bar's pending indicator is
        what tells the operator work is backed up; the input
        stays open regardless.
        """
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
            self._update_status()
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
        elif cmd in ('jump', 'jmp'):
            c._cmd_jump(parts)
        elif cmd == 'ai':
            self.sig_post.emit(lambda: self._select_tab(4))
            if len(parts) > 1 and parts[1].lower() in (
                    'config', 'setup', 'configure'):
                c._cmd_ai(parts)
            elif len(parts) > 1:
                q = ' '.join(parts[1:])

                def run_q():
                    self.ai_panel.entry.setText(q)
                    self.ai_panel._send()
                self.sig_post.emit(run_q)
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
            onwire = 0
            if getattr(c, '_result_poller', None) is not None:
                try:
                    onwire = c._result_poller.pending_count()
                except Exception:
                    onwire = 0
            queued = self._command_q.qsize()
            notes = []
            if onwire:
                notes.append(f"{onwire} on wire")
            if queued:
                notes.append(f"{queued} queued")
            note = ("  ·  " + "  ·  ".join(notes)) if notes else ""
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
    ap.add_argument('--safe', action='store_true',
                    help='start without restoring layout or enabling '
                         'background refresh')
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
        window = GuiApp(cfg, tp, debug=args.debug, safe=args.safe,
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