"""Hash-chained, append-only audit log.

Every entry links to the previous one, so a compromised node cannot rewrite
its own history without breaking the chain. Entries are written by the HOST,
never by the agent, so a hijacked guest can neither forge nor suppress a line.

Scope: this writes and verifies the chain LOCALLY. Shipping it off the device —
gossip to peers, or store-and-forward to a base station over an intermittent
link — is designed but not implemented.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

GENESIS = "0" * 64


@dataclass
class Entry:
    ts: float
    node: str
    role: str
    agent: str
    action: str
    target: str
    decision: str  # ALLOW | DENY | HELD
    reason: str
    quorum: str | None = None
    signers: list[str] = field(default_factory=list)
    prev: str = GENESIS
    digest: str = ""

    def compute_digest(self) -> str:
        body = asdict(self)
        body.pop("digest", None)
        blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()


class AuditChain:
    def __init__(self, node: str, path: str | Path | None = None):
        self.node = node
        self.path = Path(path) if path else None
        self.head = GENESIS
        self.entries: list[Entry] = []

    def append(self, **fields) -> Entry:
        entry = Entry(ts=time.time(), node=self.node, prev=self.head, **fields)
        entry.digest = entry.compute_digest()
        self.head = entry.digest
        self.entries.append(entry)
        if self.path:
            with self.path.open("a") as fh:
                fh.write(json.dumps(asdict(entry), separators=(",", ":")) + "\n")
        return entry

    def verify(self) -> bool:
        """Recompute the whole chain. Any edited entry breaks every link after it."""
        prev = GENESIS
        for e in self.entries:
            if e.prev != prev or e.compute_digest() != e.digest:
                return False
            prev = e.digest
        return True
