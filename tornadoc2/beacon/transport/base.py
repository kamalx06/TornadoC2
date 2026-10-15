"""Transport abstraction.

A transport owns the wire format and the listener for one way of
reaching the engine. The engine is called through the same three
methods the HTTP listener uses: `handle_checkin`, `pop_tasks`,
`store_result`. A transport never touches beacon state directly.

Adding a new transport means subclassing `Transport` and implementing
`start` and `stop`. Nothing else in the handler or engine has to
change.
"""

from __future__ import annotations


class Transport:
    """Base class for every C2 transport."""

    name = 'base'

    def __init__(self, engine, host, port, config=None):
        self.engine = engine
        self.host = host
        self.port = port
        self.config = config or {}
        self._running = False

    def start(self) -> bool:
        raise NotImplementedError

    def stop(self) -> None:
        self._running = False

    def log(self, msg: str) -> None:
        try:
            c = self.engine.handler.colors
            print(f"{c['cyan']}[{self.name.upper()}]{c['end']} {msg}")
        except Exception:
            print(f"[{self.name.upper()}] {msg}")