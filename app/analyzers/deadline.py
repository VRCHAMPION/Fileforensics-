"""Cooperative time budget shared by the analyzers.

Python threads can't be killed, so long-running loops check a Deadline and stop
early instead. The API layer additionally wraps the whole analysis in a timeout.
"""

from __future__ import annotations

import time


class Deadline:
    def __init__(self, seconds: float):
        self._end = time.monotonic() + seconds
        self.hit = False

    def expired(self) -> bool:
        if time.monotonic() >= self._end:
            self.hit = True
        return self.hit

    def remaining(self) -> float:
        return max(0.0, self._end - time.monotonic())


def unlimited() -> Deadline:
    return Deadline(10**9)
