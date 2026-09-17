"""Small adapter shared by collecting and streaming parser entry points."""

from __future__ import annotations

from typing import Callable


class RowSink:
    """Keep legacy list results, or emit completed rows without retaining them.

    Parsers must finish a row before append: an emitter can serialize it
    immediately. Callback failures propagate and do not increment the count.
    """

    def __init__(self, emit: Callable[[dict], None] | None = None):
        self.rows: list[dict] = []
        self.count = 0
        self._emit = emit

    def append(self, row: dict) -> None:
        if self._emit is None:
            self.rows.append(row)
        else:
            self._emit(row)
        self.count += 1
