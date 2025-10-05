"""Progress tracking utilities."""

from __future__ import annotations

from typing import List


class ProgressGuard:
    """Detect repeated tool call signatures to force finalization."""

    def __init__(self, window: int, patience: int):
        self.window = max(1, window)
        self.patience = max(1, patience)
        self.history: List[str] = []
        self.stalls = 0

    def note(self, signature: str) -> None:
        self.history.append(signature)
        if len(self.history) > self.window:
            self.history.pop(0)
        if len(self.history) == self.window and len(set(self.history)) == 1:
            self.stalls += 1
        else:
            self.stalls = 0

    def should_finalize(self) -> bool:
        return self.stalls >= self.patience


__all__ = ["ProgressGuard"]
