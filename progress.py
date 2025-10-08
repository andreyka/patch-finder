"""Agent progress tracking logic."""

from __future__ import annotations

from typing import List


class ProgressGuard:
    """Detect repeated tool call signatures to force finalization.
    
    This class tracks recent tool call signatures and detects when the
    agent is stuck in a loop, calling the same tools repeatedly without
    making progress.
    
    Attributes:
        window: Number of recent signatures to track.
        patience: How many times the window can repeat before forcing stop.
        history: List of recent tool call signatures.
        stalls: Count of how many times the window has repeated.
    """

    def __init__(self, window: int, patience: int):
        self.window = max(1, window)
        self.patience = max(1, patience)
        self.history: List[str] = []
        self.stalls = 0

    def note(self, signature: str) -> None:
        """Record a new tool call signature.
        
        Args:
            signature: The signature to record.
        """
        self.history.append(signature)
        if len(self.history) > self.window:
            self.history.pop(0)
        if len(self.history) == self.window and len(set(self.history)) == 1:
            self.stalls += 1
        else:
            self.stalls = 0

    def should_finalize(self) -> bool:
        """Check if the agent should be forced to finalize.
        
        Returns:
            True if too many repeated tool calls have been detected.
        """
        return self.stalls >= self.patience


__all__ = ["ProgressGuard"]
