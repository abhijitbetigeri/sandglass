"""The effector — the only thing in the system that touches the real world.

It lives in the host process. It is never mounted into a sandbox and the guest
holds no handle to it. In a real deployment these methods drive a relay, a
payment rail, or a deploy pipeline; here they move in-memory state so the
demo has something honest to show.
"""
from __future__ import annotations


class Effector:
    def __init__(self):
        self.targets = {"breaker-B": "CLOSED", "breaker-C": "OPEN", "feeder-A": "CLOSED"}
        self.ledger = 0.0

    def apply(self, action: str, target: str) -> str:
        if action == "grid.actuate":
            cur = self.targets.get(target, "CLOSED")
            new = "OPEN" if cur == "CLOSED" else "CLOSED"
            self.targets[target] = new
            return f"{target} {cur} -> {new}"
        if action == "funds.transfer":
            return f"transferred {target}"
        if action == "deploy.push":
            return f"deployed {target}"
        # Reversible, in-sandbox-ish actions the host merely records.
        return "ok"
